#include <linux/bpf.h>
#include "map_creator.h"
#include <linux/in.h>
#include <linux/in6.h>
/*

Compile Successfully with Clang

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv4_cidr);
	__type(value, struct banned_cidr_info);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 102400);
} banned_ipv4_cidr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv6_cidr);
	__type(value, struct banned_cidr_info);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 102400);
} banned_ipv6_cidr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct accessed_ip_info);
	__uint(max_entries, 102400);
} banned_ipv4_ip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct in6_addr);
	__type(value, struct accessed_ip_info);
	__uint(max_entries, 102400);
} banned_ipv6_ip_map SEC(".maps");

*/

/*struct bpf_map_def SEC("maps") banned_ipv6_cidr_map = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size    = sizeof(struct ipv6_cidr),
    .value_size  = sizeof(struct banned_cidr_info),
    .max_entries = 102400,
    .map_flags   = BPF_F_NO_PREALLOC
};*/

/*BPF_TABLE_SHARED can not be used for lpm_trie, for its a macro of BPF_TABLE, and BPF_TABLE's flag is set to 0*/

BPF_TABLE_SHARED_LPM(banned_ipv4_cidr_map, struct ipv4_cidr, struct banned_cidr_info, 10240);
BPF_TABLE_SHARED_LPM(banned_ipv6_cidr_map, struct ipv6_cidr, struct banned_cidr_info, 10240);

/*Save the banned cidr info*/
//BPF_TABLE_SHARED("lpm_trie", struct ipv4_cidr, struct banned_cidr_info, banned_ipv4_cidr_map, 255);
//BPF_TABLE_SHARED("lpm_trie", struct ipv6_cidr, struct banned_cidr_info, banned_ipv6_cidr_map, 102400);
/*Save access info of the banned ips*/
BPF_TABLE_SHARED("hash", __u32, struct accessed_ip_info, banned_ipv4_ip_map, 102400);
BPF_TABLE_SHARED("hash", struct in6_addr, struct accessed_ip_info, banned_ipv6_ip_map, 102400);
/*Save the start time of the machine，Set to false for the usage is implemented in python*/
/*BPF_TABLE_SHARED("hash", bool, __u64, ntp_map, 102400);*/


