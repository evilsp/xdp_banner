#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include "map_creator.h"


BPF_TABLE("extern", struct ipv4_cidr, struct banned_cidr_info, banned_ipv4_cidr_map, 1024);
BPF_TABLE("extern", struct ipv6_cidr, struct banned_cidr_info, banned_ipv6_cidr_map, 1024);
BPF_TABLE("extern", __u32, struct accessed_ip_info, banned_ipv4_ip_map, 102400);
BPF_TABLE("extern", struct in6_addr, struct accessed_ip_info, banned_ipv6_ip_map, 102400);

/*struct banned_cidr_info {
    __u64 init_time;
    __u64 timeout_time;
    bool type;
    bool status;
};*/

static __always_inline void be32_to_u8_array(__be32 be_value, __u8 data[4]) {
    data[0] = (__u8)(be_value >> 24);
    data[1] = (__u8)(be_value >> 16);
    data[2] = (__u8)(be_value >> 8);
    data[3] = (__u8)(be_value);
}

static __always_inline int if_tcp__rst_send(struct iphdr *ip, int protocol, void *data_end,  struct accessed_ip_info *ip_info_ptr){
    struct tcphdr *tcph = (void *)ip + (protocol == 6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
    /*If not tcp packet*/
    if (((void *)tcph + sizeof(*tcph) > data_end) || (ip_info_ptr->tcp_send == 1))
        goto out;

    if (tcph->ack == 1 || tcph->fin == 1){
        tcph->fin = 0;
        tcph->ack = 0;
        // Set Rst
        tcph->rst = 1;
        ip_info_ptr->tcp_send = 1;
        bpf_trace_printk("Send RST to an existed connection in ban list");
        return 0;
    }

out:
    return 1;
}


int mirrors_banner(struct xdp_md *ctx) {
    void *data = (void *)(uintptr_t)ctx->data;
    void *data_end = (void *)(uintptr_t)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        goto pass;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        goto pass;

    struct banned_cidr_info *info = NULL;
    struct accessed_ip_info ip_info = {
        .timestamp = 0,
        .access_times = 0,
        .tcp_send = 0,  // Add this line to initialize tcp_send
    };
    struct accessed_ip_info *ip_info_ptr = &ip_info;

    if (ip->version == 6) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)ip;
        if ((void *)ip6 + sizeof(*ip6) > data_end)
            goto pass;

        /*Init struct ipv6_cidr*/
        struct ipv6_cidr current_cidr_v6 = {
            .prefixlen = 128
        };

        /*GCC built-in func.Copy mem from B to A with X bytes*/
        __builtin_memcpy(current_cidr_v6.data, ip6->saddr.s6_addr, 16);

        info = banned_ipv6_cidr_map.lookup(&current_cidr_v6);

        if (info != NULL){

            /*Invalid*/
            if (info->status == 0){
                goto pass;
            }

            __u64 ipv6_fore_data = ((__u64)ip6->saddr.s6_addr32[0] << 32) | ip6->saddr.s6_addr32[1];
            __u64 ipv6_after_data = ((__u64)ip6->saddr.s6_addr32[2] << 32) | ip6->saddr.s6_addr32[3];

            // Debug
            bpf_trace_printk("Banned V6 IP: %llx %llx is Accessing", ipv6_fore_data, ipv6_after_data);

            struct in6_addr *ipv6_ip = &(ip6->saddr);
            ip_info_ptr = banned_ipv6_ip_map.lookup_or_try_init(ipv6_ip, &ip_info);

            if (ip_info_ptr == NULL){
                goto drop;
            } else {
                ip_info_ptr->timestamp = bpf_ktime_get_ns();
                ip_info_ptr->access_times += 1;
            }

            if (if_tcp__rst_send(ip, 6, data_end, ip_info_ptr) == 0){
                goto pass;
            }

            goto drop;
        }

    } else if (ip->version == 4) {

        /*Init struct ipv4_cidr*/
        struct ipv4_cidr current_cidr_v4 = {
            .prefixlen = 32
        };

        /*Trans v4 IP to little endian in order to compare*/
        __be32 ipv4_addr = bpf_ntohl(ip->saddr);
        be32_to_u8_array(ipv4_addr, current_cidr_v4.data);

        info = banned_ipv4_cidr_map.lookup(&current_cidr_v4);

        if (info != NULL){

            /*Invalid*/
            if (info->status == 0){
                goto pass;
            }

            // Debug
            bpf_trace_printk("Banned V4 IP: %x is Accessing", ip->saddr);

            ip_info_ptr = banned_ipv4_ip_map.lookup_or_try_init(&(ip->saddr), &ip_info);

            if (ip_info_ptr == NULL){
                goto drop;
            } else {
                ip_info_ptr->timestamp = bpf_ktime_get_ns();
                ip_info_ptr->access_times += 1;
            }

            if (if_tcp__rst_send(ip, 4, data_end, ip_info_ptr) == 0){
                goto pass;
            }

            goto drop;
        }
    }

pass:

    return XDP_PASS;

drop:

    return XDP_DROP;

}
