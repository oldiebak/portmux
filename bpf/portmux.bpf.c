#include "common.h"
// sk_lookup 程序需要 (bpf target 下 UAPI 头里的定义不可用, 直接给常量)
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// ---- 编译期随机化: build.sh 通过 -DPM_TOKEN=<8位随机hex> 重写所有标识符,
//      默认 token 用于开发构建。程序名/map名/pin路径全部随 token 变化。----
#ifndef PM_TOKEN
#define PM_TOKEN defaul
#endif

#define PM_CAT2(a, b) a##b
#define PM_CAT(a, b) PM_CAT2(a, b)
#define PM_STR2(x) #x
#define PM_STR(x) PM_STR2(x)

#define PM_CFG_MAP    PM_CAT(pc_, PM_TOKEN)
#define PM_WATCH_MAP  PM_CAT(pw_, PM_TOKEN)
#define PM_SOCK_MAP   PM_CAT(ps_, PM_TOKEN)
#define PM_KNOCK_MAP  PM_CAT(kn_, PM_TOKEN)
#define PM_SEC_MAIN   PM_STR(PM_CAT(sec_, PM_TOKEN))
#define PM_SEC_LEGACY PM_STR(PM_CAT(secl_, PM_TOKEN))
#define PM_PROG_NAME  PM_CAT(pi_, PM_TOKEN)
#define PM_PROG_LEGACY PM_CAT(pl_, PM_TOKEN)
#define PM_SKLOOKUP_FN PM_CAT(sk_, PM_TOKEN)
#define PM_DBG_MAP PM_CAT(pd_, PM_TOKEN)
#define PM_TUPLE_MAP PM_CAT(pt_, PM_TOKEN)

// ---- 敲门节流 (防在线爆破): 每源IP在窗口内最多 KNOCK_MAX 次 magic 敲门 ----
#define KNOCK_WINDOW_NS (60ULL * 1000000000ULL)
#define KNOCK_MAX 5

struct knock_state {
    __u64 first_ts;
    __u32 count;
    __u32 _pad;   // 显式填满: 老内核 verifier 要求 map value 全字节初始化
};

// 已敲门的四元组: tc 记录, sk_lookup 据此把连接导向监听 socket
struct knock_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct agent_config);
} PM_CFG_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_WATCH_PORTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u16);
} PM_WATCH_MAP SEC(".maps");

// 原生重定向: 存放 agent 监听 socket (Go 端插入), bpf_sk_assign 直接投递,
// 不需要 iptables / route_localnet / conntrack 改写
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u32);
} PM_SOCK_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct knock_state);
} PM_KNOCK_MAP SEC(".maps");

// 已敲门四元组 (tc → sk_lookup 共享)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct knock_tuple);
    __type(value, __u64);
} PM_TUPLE_MAP SEC(".maps");

// 调试: 统计 sk_lookup 命中 (key=1 命中 / key=2 未命中)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} PM_DBG_MAP SEC(".maps");

// 公共匹配逻辑: 解析 ETH/IP/TCP → watch 端口 → enabled → ISN magic
static __always_inline int pm_match(struct __sk_buff *skb, void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    if (ip->protocol != IPPROTO_TCP)
        return 0;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return 0;
    if (!tcp->syn || tcp->ack)
        return 0;

    // tcp->dest 是网络字节序, 转主机序与 map 中的主机序端口值比较
    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 matched = 0;
    for (int i = 0; i < MAX_WATCH_PORTS; i++) {
        __u32 key = i;
        __u16 *port = bpf_map_lookup_elem(&PM_WATCH_MAP, &key);
        if (!port || *port == 0)
            break;
        if (*port == dport) {
            matched = 1;
            break;
        }
    }
    if (!matched)
        return 0;

    __u32 key0 = 0;
    struct agent_config *cfg = bpf_map_lookup_elem(&PM_CFG_MAP, &key0);
    if (!cfg || !cfg->enabled)
        return 0;

    __u32 isn_h = bpf_ntohl(tcp->seq);
    __u16 check = (__u16)(isn_h >> 16);
    if (check != cfg->magic_prefix)
        return 0;
    return 1;
}

// 敲门节流: 超频直接拒绝 (不重定向), 限制 16bit magic 的在线爆破速率
static __always_inline int pm_knock_ok(__u32 src_ip) {
    struct knock_state *ks = bpf_map_lookup_elem(&PM_KNOCK_MAP, &src_ip);
    __u64 now = bpf_ktime_get_ns();
    if (!ks) {
        struct knock_state init = {};
        init.first_ts = now;
        init.count = 1;
        bpf_map_update_elem(&PM_KNOCK_MAP, &src_ip, &init, BPF_ANY);
        return 1;
    }
    if (now - ks->first_ts > KNOCK_WINDOW_NS) {
        ks->first_ts = now;
        ks->count = 1;
        return 1;
    }
    ks->count++;
    if (ks->count > KNOCK_MAX)
        return 0;
    return 1;
}

// 主程序: 原生 eBPF 重定向 (bpf_sk_assign), 无 iptables / 无 NAT / 无 sysctl 改动
SEC(PM_SEC_MAIN)
int PM_PROG_NAME(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    if (!pm_match(skb, data, data_end))
        return 0;

    struct iphdr *ip = (void *)((struct ethhdr *)data + 1);
    if (!pm_knock_ok(ip->saddr))
        return 0;

    // 记录已敲门的四元组 (sk_lookup 程序在 socket 查找层读取并转向)
    struct tcphdr *tcp = (void *)((struct iphdr *)((struct ethhdr *)data + 1) + 1);
    struct knock_tuple t = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&PM_TUPLE_MAP, &t, &now, BPF_ANY);
    __u32 dkey = 1;
    __u64 *cnt = bpf_map_lookup_elem(&PM_DBG_MAP, &dkey);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&PM_DBG_MAP, &dkey, &one, BPF_ANY);
    }
    return 0;
}

// sk_lookup: 内核 socket 查找层的原生转向 (NAT-less, SYN-ACK 使用原始元组)
SEC("sk_lookup")
int PM_SKLOOKUP_FN(struct bpf_sk_lookup *ctx) {
    if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
        return SK_PASS;

    struct knock_tuple t = {
        .saddr = ctx->remote_ip4,
        .daddr = ctx->local_ip4,
        .sport = ctx->remote_port,
        .dport = ctx->local_port,
    };
    __u64 *ts = bpf_map_lookup_elem(&PM_TUPLE_MAP, &t);
    if (!ts) {
        __u32 dkey = 2;
        __u64 *cnt = bpf_map_lookup_elem(&PM_DBG_MAP, &dkey);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }
        return SK_PASS;
    }
    __u64 now = bpf_ktime_get_ns();
    if (now - *ts > 10ULL * 1000000000ULL) {
        bpf_map_delete_elem(&PM_TUPLE_MAP, &t);
        return SK_PASS;
    }

    __u32 key0 = 0;
    struct bpf_sock *sk = bpf_map_lookup_elem(&PM_SOCK_MAP, &key0);
    if (!sk)
        return SK_PASS;
    // 原生转向必须经 bpf_sk_assign helper (直接写 ctx->sk 被 verifier 拒绝);
    // 赋值后释放 map 持有的引用 (老内核 verifier 要求显式 release)
    bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return SK_PASS;
}

// 回退程序: 老内核不支持 bpf_sk_assign 时用 mark + iptables DNAT (legacy 模式)
SEC(PM_SEC_LEGACY)
int PM_PROG_LEGACY(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    if (!pm_match(skb, data, data_end))
        return 0;

    struct iphdr *ip = (void *)((struct ethhdr *)data + 1);
    if (!pm_knock_ok(ip->saddr))
        return 0;

    skb->mark = 0x706d0001;
    return 0;
}

char _license[] SEC("license") = "GPL";
