from bcc import BPF
import socket
import struct
import logging
from ctypes import Structure, c_uint8, c_uint16, c_uint32, c_uint64, Union
import ipaddress
import os
import fcntl


class BannedIpInfo(Structure):
    _fields_ = [
        ("timestamp", c_uint64),
        ("access_times", c_uint64)
    ]

# 实际在被获取时，其转为了一个对象，因此如果成员名带有 __，可能会被判定为私有导致无法从外部访问
class In6AddrUnion(Union):
    _fields_ = [
        ("u6_addr8", c_uint8 * 16),
        ("u6_addr16", c_uint16 * 8),
        ("u6_addr32", c_uint32 * 4)
    ]


class In6Addr(Structure):
    _anonymous_ = ("in6_u",)
    _fields_ = [
        ("in6_u", In6AddrUnion),
    ]


class BannedIpXdpMap(object):
    """
        Used to modify mirrors_banner xdp map
    """

    def __init__(self, map_location: str, v4_banned_list_location: str = None, v6_banned_list_location: str = None):

        # Get file location
        self.v4_banned_ip_list_location = v4_banned_list_location
        self.v6_banned_ip_list_location = v6_banned_list_location
        # Load ips in file to ebpf map
        bpf_map_file = BPF(src_file=map_location)
        self.ipv4_map = bpf_map_file.get_table("banned_ipv4_map")
        self.ipv6_map = bpf_map_file.get_table("banned_ipv6_map")
        # Cancel auto load
        self.banlist_v4 = BanList(self.v4_banned_ip_list_location, load=False)
        self.banlist_v6 = BanList(self.v6_banned_ip_list_location, load=False)
        self.load_banned_list_file()

    def load_banned_list_file(self):
        """
            Banned ips should be one ip per line
        """
        # Clear maps
        self.ipv4_map.clear()
        self.ipv6_map.clear()

        # Load V4 ips
        if self.v4_banned_ip_list_location:
            self.banlist_v4.load_banlist()
            v4_ips = self.banlist_v4.banlist
            for ip in v4_ips:
                ip_info = BannedIpInfo()
                ip_info.timestamp = 0
                ip_info.access_times = 0
                ip_int = convert_ip_to_u32(ip)
                self.ipv4_map[c_uint32(ip_int)] = ip_info

        # Load V6 ips
        if self.v6_banned_ip_list_location:
            self.banlist_v6.load_banlist()
            v6_ips = self.banlist_v6.banlist
            for ip in v6_ips:
                ip_info = BannedIpInfo()
                ip_info.timestamp = 0
                ip_info.access_times = 0
                addr = ipv6_to_in6_addr(ip)
                self.ipv6_map[addr] = ip_info

    def add_ip_to_ban_list_with_cidr(self, cidr):
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = network.hosts()
            skip_list = []
            if network.version == 4:
                for ip in hosts:
                    ip_str = str(ip)
                    ip_int = convert_ip_to_u32(ip_str)
                    convert_ip_int = c_uint32(ip_int)
                    # bcc iter object do not support 'in'
                    try:
                        self.ipv4_map[convert_ip_int]
                        skip_list.append(ip_str)
                    except:
                        # write after log
                        self.banlist_v4.add_ip(ip_str)
                        ip_info = BannedIpInfo()
                        ip_info.timestamp = 0
                        ip_info.access_times = 0
                        self.ipv4_map[convert_ip_int] = ip_info
            # if ipv6
            else:
                for ip in hosts:
                    ip_str = str(ip)
                    v6_struct = ipv6_to_in6_addr(ip_str)
                    # bcc iter object do not support 'in'
                    try:
                        self.ipv6_map[v6_struct]
                        skip_list.append(ip_str)
                    except:
                        # write after log
                        self.banlist_v6.add_ip(ip_str)
                        ip_info = BannedIpInfo()
                        ip_info.timestamp = 0
                        ip_info.access_times = 0
                        self.ipv6_map[v6_struct] = ip_info
            logging.info(f"CIDR: {cidr} have been added successfully, IP list {skip_list} have been skipped for they have been existed")
            return True
        except ValueError as e:
            logging.error(f"Failed to add CIDR: {cidr} to Map due to {e}, some IPs may heve been added")
            return False

    def remove_ip_from_ban_list_with_cidr(self, cidr):
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = network.hosts()
            skip_list = []
            if network.version == 4:
                for ip in hosts:
                    ip_str = str(ip)
                    ip_int = convert_ip_to_u32(ip_str)
                    convert_ip_int = c_uint32(ip_int)
                    # bcc iter object do not support 'in'
                    try:
                        self.ipv4_map[convert_ip_int]
                        self.banlist_v4.remove_ip(ip_str)
                        self.ipv4_map.pop(convert_ip_int)
                    except:
                        skip_list.append(ip_str)
            # if ipv6
            else:
                for ip in hosts:
                    ip_str = str(ip)
                    v6_struct = ipv6_to_in6_addr(ip_str)
                    # bcc iter object do not support 'in'
                    try:
                        self.ipv6_map[v6_struct]
                        self.banlist_v6.remove_ip(ip_str)
                        self.ipv6_map.pop(v6_struct)
                    except:
                        skip_list.append(ip_str)
            logging.info(f"CIDR: {cidr} have been removed successfully, IP list {skip_list} have been skipped for they are not existed")
            return True
        except KeyError as e:
            logging.error(f"Failed to remove CIDR {str(cidr)} from Map due to {e}, some IPs may heve been removed")
            return False


class BannedIpXdpProg(object):
    """
        Used to modify mirrors_banner xdp prog
    """

    def __init__(self, prog_location: str, func_name: str):

        # init bpf prog
        self.bpf_file = BPF(src_file=prog_location)
        self.mirrors_banner_fn = self.bpf_file.load_func(func_name, BPF.XDP)

    def attach_xdp_prog(self, net_device: str, attach_type: int):
        """
        This function attaches ban_ip XDP (eXpress Data Path) program to the specified network device.

        Args:
            net_device (str): The name of the network device to attach the XDP program to.
            attach_type (int): The type of XDP program attachment. Typically, this can be
                               0 for BPF_XDP_FLAGS_SKB_MODE or 1 for BPF_XDP_FLAGS_DRV_MODE.

        Returns:
            bool: True if attachment succeeds, False otherwise.
        """
        try:
            self.bpf_file.attach_xdp(net_device, self.mirrors_banner_fn, attach_type)
            logging.info(f"XDP program attached successfully to device: {net_device}")
            return True
        except Exception as e:
            logging.error(f"Failed to attach XDP program to device {net_device}: {e}")
            return False

    def remove_xdp_prog(self, net_device: str, attach_type: int):

        try:
            self.bpf_file.remove_xdp(net_device, attach_type)
            logging.info("XDP program removed successfully on device: {net_device}")
            return True
        except Exception as e:
            logging.error(f"Failed to remove XDP program on device {net_device}: {e}")
            return False


class BanList:
    def __init__(self, filepath, load=True):
        self.filepath = filepath
        self.banlist = set()
        if load:
            self.load_banlist()

    def load_banlist(self):
        """加载 banlist 文件到内存"""
        self.banlist.clear()
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                for line in f:
                    self.banlist.add(line.strip())

    def add_ip(self, ip):
        """添加 IP 到 banlist"""
        if ip not in self.banlist:
            self.banlist.add(ip)
            self._write_ip_to_file(ip)

    def remove_ip(self, ip):
        """从 banlist 中移除 IP"""
        if ip in self.banlist:
            self.banlist.remove(ip)
            self._rewrite_banlist()

    def _write_ip_to_file(self, ip):
        """将新的 IP 追加到 banlist 文件"""
        with open(self.filepath, 'a') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(ip + '\n')
            fcntl.flock(f, fcntl.LOCK_UN)

    def _rewrite_banlist(self):
        """重写 banlist 文件"""
        with open(self.filepath, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            for ip in self.banlist:
                f.write(ip + '\n')
            fcntl.flock(f, fcntl.LOCK_UN)

    def is_banned(self, ip):
        """检查 IP 是否在 banlist 中"""
        return ip in self.banlist


def ipv6_to_in6_addr(ipv6_address):
    packed_ip = socket.inet_pton(socket.AF_INET6, ipv6_address)
    addr = In6Addr()
    # Assign to __u6_addr8
    for i in range(16):
        addr.u6_addr8[i] = packed_ip[i]
    # Assign to __u6_addr16
    for i in range(8):
        addr.u6_addr16[i] = struct.unpack('<H', packed_ip[2 * i:2 * i + 2])[0]
    # Assign to __u6_addr32
    for i in range(4):
        addr.u6_addr32[i] = struct.unpack('<I', packed_ip[4 * i:4 * i + 4])[0]
    return addr


# Transfer ip to bytes
def convert_ip_to_u32(ip):
    # x86 use little endian
    packed_ip = socket.inet_aton(ip)
    u32_ip = struct.unpack('<I', packed_ip)[0]
    return u32_ip


# Transfer bytes to ipv4
def convert_u32_to_ip(ip_bytes):
    ip_int = struct.unpack('<I', ip_bytes)[0]  # 小端序解包
    ip_address = socket.inet_ntoa(struct.pack('!I', ip_int))  # 大端序打包
    return '.'.join(ip_address.split('.')[::-1])


# Transfer bytes to ipv6
def in6_addr_to_ipv6(addr):
    packed_ip = bytearray(16)
    # Extract from __u6_addr8
    for i in range(16):
        packed_ip[i] = addr[i]
    # Convert packed_ip back to IPv6 string
    ipv6_address = socket.inet_ntop(socket.AF_INET6, bytes(packed_ip))
    return ipv6_address
