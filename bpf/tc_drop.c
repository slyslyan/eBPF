// bpf/tc_drop.c — eBPF TC 程序，根据 IP 地址在内核层直接丢包
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#define ETH_P_IP    0x0800

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);      // 目标 IP（网络字节序）
    __type(value, __u8);     // 占位值
} tc_drop_ips SEC(".maps");

SEC("tc")
int tc_drop_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(__u64)skb->data_end;
    void *data     = (void *)(__u64)skb->data;

    // 以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    // 仅处理 IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // IP 头
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    // 查询 drop map，命中则丢包
    __u32 dst_ip = ip->daddr;
    if (bpf_map_lookup_elem(&tc_drop_ips, &dst_ip)) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
