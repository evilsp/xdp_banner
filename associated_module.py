import logging
import os
from wasted.cidr_lib import str_to_cidr
from ctypes import Structure, c_uint8, c_uint16, c_uint32, c_uint64, c_bool, Union, c_ubyte
import socket
import time
import fcntl
import shutil
import struct
import ipaddress

class Ipv4Cidr(Structure):
    _fields_ = [
        ("prefixlen", c_uint32),
        ("data", c_ubyte * 4)
    ]

class Ipv6Cidr(Structure):
    _fields_ = [
        ("prefixlen", c_uint32),
        ("data", c_ubyte * 16)
    ]


def parse_cidr(cidr_str):
    try:
        return __parse_cidr(cidr_str)
    except ipaddress.AddressValueError:
        logging.error("Invalid CIDR string")
        return None

def __parse_cidr(cidr_str):
    # 解析 IPv6 CIDR
    network = ipaddress.ip_network(cidr_str, strict=False)

    # 提取前缀长度
    prefixlen = network.prefixlen

    # 提取网络地址并转换为字节数组
    network_address = network.network_address.packed

    if network.version == 4:
        ipv4_cidr = Ipv4Cidr()
        ipv4_cidr.prefixlen = prefixlen
        # Small Endian to Big Endian
        # ipv4_cidr.data[:] = struct.pack('!I', struct.unpack('<I', network_address)[0])
        ipv4_cidr.data[:] = network_address
        return ipv4_cidr

    else:
        ipv6_cidr = Ipv6Cidr()
        ipv6_cidr.prefixlen = prefixlen
        # 由于 LPM Map 特性，不需要在此处做大小端序转换
        # ipv6_cidr.data[:] =  struct.pack('!I', struct.unpack('<16B', network_address)[0])
        ipv6_cidr.data[:] = network_address
        return ipv6_cidr


# Avoid circle import
class BannedCidrInfo(Structure):
    _fields_ = [
        ("init_time", c_uint64),
        ("timeout_time", c_uint64),
        # 0 为暂时，1 为永久
        ("type", c_bool),
        # 0 为失效，1 为有效
        ("status", c_bool)
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


class BanList:
    def __init__(self, filepath, persistence_path, protocol: int=4, load=True):
        """
        Read filepath after load persistence_path
        """
        self.filepath = filepath
        self.persistence_path = persistence_path
        if protocol not in [4,6]:
           raise ValueError("Wrong protocol, choose 4 or 6")
        self.protocol = protocol
        self.int_check = lambda s: s.lstrip('-').isdigit()
        # cidr to element map
        self.element_map = {}
        # cidr to struct cidr
        self.cidr_map = {}
        # Save used cidr blocks
        self.cidr_list = set()
        if load:
            self.full_reload_banlist()

    def full_reload_banlist(self):
        """
        Reload banlist fully
        """
        # Set False to override persistence_config
        self.load_banlist(self.persistence_path, clear_enable=True)
        self.load_banlist(self.filepath, clear_enable=False)

    def load_banlist(self, file_path, clear_enable:bool = True):
        """
        Load banlist file to cidr_list and element_list，
        """
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                # Preparing, set lock to file
                fcntl.flock(f, fcntl.LOCK_EX)
                # Clear cidr_list and element_map
                if clear_enable:
                    self.cidr_list.clear()
                    self.cidr_map.clear()
                    self.element_map.clear()
                # Start Reload
                for line in f:
                    line = line.strip('\n')
                    # Skip #
                    if line.startswith("#"):
                        continue
                    elements = line.split(' ')
                    # Trans to cidr block
                    cidr_struct = parse_cidr(elements[0])
                    # Check if is allowed
                    if cidr_struct is None or \
                            len(elements) < 5 or \
                                self.int_check(elements[1]) is False or \
                                    self.int_check(elements[2]) is False or \
                                        elements[3] not in ["0", "1"] or \
                                            elements[4] not in ["0", "1"]:
                        logging.error(f'{line} 不满足规则，本步解析跳过')
                        continue
                    # Save cidr to cidr_list
                    if elements[0] not in self.cidr_list:
                        self.cidr_list.add(elements[0])
                    # Save cidr to element_map
                    info = BannedCidrInfo()
                    info.init_time = int(elements[1])
                    info.timeout_time = int(elements[2])
                    info.type = int(elements[3])
                    info.status = int(elements[4])
                    self.element_map[elements[0]] = info
                    self.cidr_map[elements[0]] = cidr_struct
                    # Class CIDR not implement __eq__ and __hash__, so it couldn't be keys
                    # self.element_map[cidr_struct] = info
                    logging.info(f'{line} 满足规则，已成功被解析')
                    logging.debug(f'{line} 满足规则，已成功被解析。init_time: {info.init_time}, timeout_time: {info.timeout_time}, type: {info.type}, status: {info.status}')

    def update_cidr(self, cidr: str, is_cidr_permanently_banned: int, ban_time: int = 0):
        """
        This function update cidr to cidr_list and element_list

        Args:
            cidr (str): The cidr which will be updated.
            is_cidr_permanently_banned (int): Just as the name, 0 is temporarily, 1 is permanently
            ban_time (int, optional): If choose temporarily banned, set this to the time(s) you prefer

        Returns:
            int: 1 if cidr exists, 0 if new, -1 if error
        """
        return_code = 1
        cidr_struct = parse_cidr(cidr)
        # Check if cidr is valid and in cidr_list, and other params is valid
        if cidr is not None or \
                is_cidr_permanently_banned not in [0, 1] or \
                    isinstance(ban_time, int) is False:
            # Trans to ns
            time_now = time.time_ns()
            ban_time = time_now + ban_time * (10**9)
            status =  int(time_now < ban_time) if is_cidr_permanently_banned == 0 else 1
            info = BannedCidrInfo()
            element = f'{cidr} {time_now} {ban_time} {is_cidr_permanently_banned} {status}'
            info.init_time = time_now
            info.timeout_time = ban_time
            info.type = is_cidr_permanently_banned
            info.status = status
            # Check if should new a cidr block
            if cidr not in self.cidr_list:
                self.cidr_list.add(cidr)
                return_code = 0
            self.element_map[cidr] = info
            self.cidr_map[cidr] = cidr_struct
            self.write_element_to_file(element)
            return return_code
        logging.error(f'Add cidr error：Params [{cidr}, {is_cidr_permanently_banned}, {ban_time}] is not valid')
        return -1

    def check_cidr(self,cidr):
        """
            Check if cidr exists
        """
        if cidr in self.cidr_list:
            return 0
        return 1

    def remove_cidr(self, cidr:str, rewrite_enable:bool = True):
        """从 cidr_list 中移除 IP"""
        if not isinstance(rewrite_enable,bool):
            raise ValueError("rewrite_enable should be bool！")
        if cidr in self.cidr_list:
            self.cidr_list.remove(cidr)
            self.element_map.pop(cidr)
            self.cidr_map.pop(cidr)
            if rewrite_enable:
                self.rewrite_banlist()
            return 0
        return 1

    def write_element_to_file(self, element):
        """Append new element to persistent file"""
        try:
            with open(self.persistence_path, 'a') as f:
                # Only the running process can read or write the file
                fcntl.flock(f, fcntl.LOCK_EX)
                f.write(element + '\n')
                # Multi read, one write
                fcntl.flock(f, fcntl.LOCK_UN)
        except IOError as e:
            logging.error(f"IOError occurred while appending new element to the banlist: {e}")
        except ValueError as e:
            logging.error(f"ValueError occurred while appending new element to the banlist: {e}")

    def rewrite_banlist(self):
        """Safely Rewrite persistent file"""
        try:
            with open(f"{self.persistence_path}.tmp", 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                for cidr, cidr_info in self.element_map.items():
                    element = f'{cidr} {cidr_info.init_time} {cidr_info.timeout_time} {int(cidr_info.type)} {int(cidr_info.status)}'
                    # Ensure the element is a string before writing
                    if not isinstance(element, str):
                        raise ValueError(f"Invalid element {element}, expected a string.")
                    f.write(element + '\n')
                fcntl.flock(f, fcntl.LOCK_UN)
            shutil.move(f"{self.persistence_path}.tmp", self.persistence_path)
            logging.info(f"Rewrite Banlist {self.persistence_path} successfully")
        except IOError as e:
            logging.error(f"IOError occurred while rewriting the banlist: {e}")
        except ValueError as e:
            logging.error(f"ValueError occurred while rewriting the banlist: {e}")
