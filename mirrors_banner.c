#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include "map_creator.h"

BPF_TABLE("extern", __u32, struct banned_ip_info, banned_ipv4_map, 102400);
BPF_TABLE("extern", struct in6_addr, struct banned_ip_info, banned_ipv6_map, 102400);

int mirrors_banner(struct xdp_md *ctx) {
    void *data = (void *)(uintptr_t)ctx->data;
    void *data_end = (void *)(uintptr_t)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    struct banned_ip_info *info = NULL;
    int protocol = 4;

    if (ip->version == 6) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)ip;
        if ((void *)ip6 + sizeof(*ip6) > data_end)
            return XDP_PASS;

        struct in6_addr src_ip6 = ip6->saddr;
        info = banned_ipv6_map.lookup(&src_ip6);
        protocol = 6;
    } else if (ip->version == 4) {
        __u32 src_ip = ip->saddr;
        info = banned_ipv4_map.lookup(&src_ip);
    }

    if (info == NULL)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (protocol == 6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    __u16 dest_port = bpf_ntohs(tcp->dest);
    if (dest_port == 80 || dest_port == 443) {
        info->timestamp = bpf_ktime_get_ns();
        info->access_times += 1;
        return XDP_DROP;
    }

    return XDP_PASS;

}
