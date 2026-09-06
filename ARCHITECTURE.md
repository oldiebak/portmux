# PortMux Architecture

## High-Level Design

PortMux uses a two-layer kernel filtering approach:

**Layer 1: eBPF TC Classifier** → Detects magic ISN in SYN packets, sets skb->mark
**Layer 2: iptables NAT REDIRECT** → Redirects marked packets to agent's hidden port

This avoids the `bpf_sk_assign` verifier bug found on kernel 5.15 while maintaining
all traffic at line rate in the kernel.

## Packet Flow

```
Incoming SYN → ens18:
  │
  ├─ TC BPF Ingress (SCHED_CLS, direct-action)
  │   ├── parse ETH header (EtherType == IP?)
  │   ├── parse IP header (protocol == TCP?)
  │   ├── parse TCP header (SYN? && !ACK?)
  │   ├── match dst_port against watch_ports_map
  │   ├── check agent_cfg_map.enabled
  │   ├── check ISN magic (top 16 bits == magic_prefix?)
  │   └── MATCH → skb->mark = 0x706d0001
  │   └── ALL paths → return TC_ACT_OK (0)
  │
  ├─ Netfilter PREROUTING (nat table)
  │   ├── mark 0x706d0001/0x706d0001?
  │   │   └── YES → REDIRECT --to-ports <agent_port>
  │   └── NO → normal routing
  │
  └─ Local delivery
      ├── Redirected → agent listener (127.0.0.1:<agent_port>)
      └── Normal → nginx / original service
```

## Component Diagram

```
┌────────────────────────────────────────────┐
│                Target Machine               │
│                                            │
│  ┌──────────────────────────────────┐      │
│  │       eBPF Programs (Kernel)      │      │
│  │  ┌────────────────────────────┐  │      │
│  │  │ TC Classifier (ingress)    │  │      │
│  │  │ • Section: "classifier"    │  │      │
│  │  │ • Maps:                    │  │      │
│  │  │   - agent_cfg_map (ARRAY)  │  │      │
│  │  │   - watch_ports_map(ARRAY) │  │      │
│  │  │ • Returns: TC_ACT_OK(0)    │  │      │
│  │  └────────────────────────────┘  │      │
│  └──────────────────────────────────┘      │
│                  │                         │
│  ┌───────────────▼──────────────────┐      │
│  │        iptables Rules            │      │
│  │  *nat PREROUTING                 │      │
│  │  -p tcp --dport X -m mark        │      │
│  │  --mark 0x706d0001/0x706d0001    │      │
│  │  -j REDIRECT --to-ports Y        │      │
│  └───────────────┬──────────────────┘      │
│                  │                         │
│  ┌───────────────▼──────────────────┐      │
│  │         Go Agent (Userspace)      │      │
│  │  ┌────────────────────────────┐  │      │
│  │  │ TC Attacher                │  │      │
│  │  │ iptables Manager           │  │      │
│  │  │ BPF Map Updater            │  │      │
│  │  └────────────────────────────┘  │      │
│  │  ┌────────────────────────────┐  │      │
│  │  │ TCP Listener (127.0.0.1)   │  │      │
│  │  │ Protocol Router            │  │      │
│  │  └──────────┬─────────────────┘  │      │
│  │             │                     │      │
│  │  ┌──────────┼──────────┐         │      │
│  │  ▼          ▼          ▼         │      │
│  │ shell     socks5     proxy       │      │
│  │ handler   handler    handler     │      │
│  └──────────────────────────────────┘      │
└────────────────────────────────────────────┘
```

## BPF Maps

### agent_cfg_map
- Type: BPF_MAP_TYPE_ARRAY
- Key: u32 (always 0)
- Value: struct agent_config (12 bytes)
  - agent_ip: u32 (LE host order, 127.0.0.1 = 0x0100007F)
  - agent_port: u16 (LE host order)
  - magic_prefix: u16 (LE host order, top 16 bits of ISN)
  - enabled: u8 (0 = disabled, 1 = enabled)
  - pad[3]: u8

### watch_ports_map
- Type: BPF_MAP_TYPE_ARRAY
- Key: u32 (index 0-7)
- Value: u16 (port in network byte order)

## Go Package Relationships

```
cmd/agent/main.go
  └── internal/agent/agent.go       (core daemon)
      ├── internal/agent/config.go  (config loading)
      ├── internal/agent/router.go  (fingerprint routing)
      │   └── internal/handler/*.go (protocol handlers)
      ├── internal/bpf/loader.go    (BPF ELF loading + map management)
      └── internal/stealth/process.go (hiding)

cmd/wrap/main.go
  └── unix.TCP_REPAIR  (ISN injection)
```

## ISN Encoding

```
magic_prefix = SHA256(secret_key)[0:2]    // 16 bits, big-endian
ISN = (magic_prefix << 16) | random_16    // 32 bits, host order

// Client side (wrapper):
//   1. TCP_REPAIR=1 (enter repair mode)
//   2. TCP_REPAIR_QUEUE=TCP_SEND_QUEUE
//   3. TCP_QUEUE_SEQ=<ISN in network byte order>
//   4. connect() (sets up state)
//   5. TCP_REPAIR=0 (sends SYN with custom ISN)

// Server side (BPF):
//   tcp->seq is in network byte order (big-endian)
//   bpf_ntohl(tcp->seq) → host order
//   >> 16 → extract top 16 bits
//   compare with cfg->magic_prefix
```

## Protocol Router Logic

```go
func (r *Router) Route(ctx context.Context, conn net.Conn) {
    buf := make([]byte, 64)
    n, _ := conn.Read(buf)  // peek first N bytes
    peeked := buf[:n]

    for _, rule := range r.rules { // sorted by priority
        if rule.Fingerprint == nil {  // wildcard "*"
            rule.Handler.Handle(ctx, newPeekedConn(conn, peeked))
            return
        }
        if bytes.HasPrefix(peeked, rule.Fingerprint) {
            rule.Handler.Handle(ctx, newPeekedConn(conn, peeked))
            return
        }
    }
    conn.Close()
}

// newPeekedConn prepends peeked data to the connection
// so handlers don't lose the first bytes we already read
func newPeekedConn(conn net.Conn, peeked []byte) *peekedConn {
    return &peekedConn{
        Conn:   conn,
        reader: io.MultiReader(bytes.NewReader(peeked), conn),
    }
}
```

## Stealth Mechanisms

| Mechanism | Implementation | Detection Bypass |
|-----------|---------------|------------------|
| Process name | `os.Args[0] = "[kworker/u:0]"` | `ps aux` shows kernel thread |
| Self-delete | `os.Remove(os.Executable())` | File system scanning |
| No new ports | Reuses existing service port | `ss -tlnp` unchanged |
| BPF persistence | Pinned maps (optional) | Agent process can exit |
| ISN-based magic | Standard TCP field | DPI signature evasion |
