#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include "map_creator.h"

BPF_TABLE_SHARED("hash", __u32, struct banned_ip_info, banned_ipv4_map, 102400);
BPF_TABLE_SHARED("hash", struct in6_addr, struct banned_ip_info, banned_ipv6_map, 102400);
