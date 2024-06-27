#ifndef MAP_CREATOR_H
#define MAP_CREATOR_H
#include <linux/types.h>
/*#include <stdbool.h>*/

/*Define shared LPM MAP Struct for BCC not support edit flags in BPF_TABLE_SHARED*/
/*Issue：https://github.com/iovisor/bcc/issues/5044*/
#define BPF_TABLE_SHARED_LPM(_name, _key_type, _leaf_type, _max_entries) \
BPF_F_TABLE("lpm_trie", _key_type, _leaf_type, _name, _max_entries, BPF_F_NO_PREALLOC); \
__attribute__((section("maps/shared"))) \
struct _name##_table_t __##_name


struct ipv4_cidr {
    __u32   prefixlen;  /* up to 32 for AF_INET, 128 for AF_INET6 */
    __u8    data[4];    /* Arbitrary size */
};

struct ipv6_cidr {
    __u32   prefixlen;  /* up to 32 for AF_INET, 128 for AF_INET6 */
    __u8    data[16];    /* Arbitrary size */
};

/*Save Banned CIDR Info*/
struct banned_cidr_info {
    __u64 init_time;
    __u64 timeout_time;
    bool type;
    bool status;
};

/*Save Accessed banned IP Info*/
struct accessed_ip_info {
    __u64 timestamp;
    __u64 access_times;
    bool tcp_send;
};

#endif
