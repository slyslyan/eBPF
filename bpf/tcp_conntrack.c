// bpf/tcp_conntrack.c — TCP 连接生命周期跟踪
// 测量真实的连接建立→关闭耗时（RTT），替代 tcp_sendmsg 的缓冲拷贝时间
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct conn_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8  role;       // 1=主动连接(connect), 2=被动接受(accept)
    __u8  pad;
    __u64 duration_ns; // 连接持续时间（纳秒）
    __u32 pid;
    __u8  comm[16];
    __u8  pad2[4];
};

// 连接起始时间记录 (key = sock pointer as u64)
struct conn_info {
    __u64 start_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u32 pid;
    __u8  role;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct conn_info);
} conn_track SEC(".maps");

// 连接事件 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} conn_events SEC(".maps");

// ---------- 采样/去重 ----------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} conn_rate_limit SEC(".maps");

const __u64 conn_sampling_interval_ns = 1000000000; // 1 秒

static int conn_should_sample(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    __u64 key = (__u64)saddr ^ (__u64)daddr ^ ((__u64)sport << 16) ^ (__u64)dport;
    __u64 *last = bpf_map_lookup_elem(&conn_rate_limit, &key);
    __u64 now = bpf_ktime_get_ns();
    if (last && (now - *last) < conn_sampling_interval_ns) {
        return 0;
    }
    __u64 val = now;
    bpf_map_update_elem(&conn_rate_limit, &key, &val, BPF_ANY);
    return 1;
}

// ---------- kprobe/tcp_connect — 客户端发起连接 ----------
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)ctx->di;
    if (!sk) return 0;

    __u64 sk_ptr = (__u64)sk;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct conn_info info = {};
    info.start_ns = bpf_ktime_get_ns();
    info.role = 1;  // client
    info.pid = pid;

    BPF_CORE_READ_INTO(&info.family, sk, __sk_common.skc_family);
    if (info.family == 2) {
        BPF_CORE_READ_INTO(&info.saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&info.daddr, sk, __sk_common.skc_daddr);
    } else if (info.family == 10) {
        struct in6_addr v6_rcv, v6_dst;
        BPF_CORE_READ_INTO(&v6_rcv, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&v6_dst, sk, __sk_common.skc_v6_daddr);
        info.saddr = v6_rcv.in6_u.u6_addr32[3];
        info.daddr = v6_dst.in6_u.u6_addr32[3];
    } else {
        return 0;
    }

    BPF_CORE_READ_INTO(&info.sport, sk, __sk_common.skc_num);
    __u16 dport_be;
    BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
    info.dport = __builtin_bswap16(dport_be);

    bpf_map_update_elem(&conn_track, &sk_ptr, &info, BPF_ANY);
    return 0;
}

// ---------- kprobe/tcp_close — 连接关闭 ----------
SEC("kprobe/tcp_close")
int kprobe_tcp_close(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)ctx->di;
    if (!sk) return 0;

    __u64 sk_ptr = (__u64)sk;
    struct conn_info *info = bpf_map_lookup_elem(&conn_track, &sk_ptr);
    if (!info) return 0;  // 未跟踪的连接（如 accept 侧）

    __u64 now = bpf_ktime_get_ns();
    __u64 duration_ns = now - info->start_ns;

    // 采样检查
    if (conn_should_sample(info->saddr, info->daddr, info->sport, info->dport)) {
        struct conn_event *evt = bpf_ringbuf_reserve(&conn_events, sizeof(*evt), 0);
        if (evt) {
            evt->saddr = info->saddr;
            evt->daddr = info->daddr;
            evt->sport = info->sport;
            evt->dport = info->dport;
            evt->family = info->family;
            evt->role = info->role;
            evt->duration_ns = duration_ns;
            evt->pid = info->pid;
            bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
            bpf_ringbuf_submit(evt, 0);
        }
    }

    bpf_map_delete_elem(&conn_track, &sk_ptr);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
