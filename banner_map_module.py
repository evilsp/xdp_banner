from bcc import BPF
import logging
from ctypes import Structure, c_uint32, c_uint64,  c_bool
import time
import ipaddress
from associated_module import BanList, convert_ip_to_u32, convert_u32_to_ip

class BannedIpInfo(Structure):
    _fields_ = [
        ("timestamp", c_uint64),
        ("access_times", c_uint64)
    ]

class BannedCidrInfo(Structure):
    _fields_ = [
        ("init_time", c_uint64),
        ("timeout_time", c_uint64),
        # 0 为暂时，1 为永久
        ("type", c_bool),
        # 0 为失效，1 为有效
        ("status", c_bool)
    ]

class BannedIpXdpMap(object):
    """
        Used to modify mirrors_banner xdp map
    """

    def __init__(self, v4_banned_list_location: str , v6_banned_list_location: str ,
                 v4_banned_list_persistence_location , v6_banned_list_persistence_location):

        # Get file location
        self.v4_banned_ip_list_location = v4_banned_list_location
        self.v4_banned_ip_list_persistence_location = v4_banned_list_persistence_location
        self.v6_banned_ip_list_location = v6_banned_list_location
        self.v6_banned_ip_list_persistence_location = v6_banned_list_persistence_location
        # Load ips in file to ebpf map
        bpf_map_file = BPF(src_file="./map_creator.c")
        self.ipv4_cidr_map = bpf_map_file.get_table("banned_ipv4_cidr_map")
        self.ipv6_cidr_map = bpf_map_file.get_table("banned_ipv6_cidr_map")
        self.ipv4_access_map = bpf_map_file.get_table("banned_ipv4_ip_map")
        self.ipv6_access_map = bpf_map_file.get_table("banned_ipv6_ip_map")
        # Enable auto load
        self.banlist_v4 = BanList(self.v4_banned_ip_list_location, self.v4_banned_ip_list_persistence_location, protocol= 4)
        self.banlist_v6 = BanList(self.v6_banned_ip_list_location, self.v6_banned_ip_list_persistence_location, protocol= 6)
        self.load_banned_list_file()

    def load_banned_list_file(self):
        """
            Banned ips should be one ip per line
        """
        # Load V4 ips
        if self.v4_banned_ip_list_location:
            # Clear maps
            self.banlist_v4.full_reload_banlist()
            self.ipv4_cidr_map.clear()
            for cidr in self.banlist_v4.cidr_list:
                self.ipv4_cidr_map[self.banlist_v4.cidr_map[cidr]] = self.banlist_v4.element_map[cidr]

        # Load V6 ips
        if self.v6_banned_ip_list_location:
            # Clear maps
            self.banlist_v6.full_reload_banlist()
            self.ipv6_cidr_map.clear()
            for cidr, cidr_info in self.banlist_v6.element_map.items():
                self.ipv6_cidr_map[self.banlist_v6.cidr_map[cidr]] = self.banlist_v6.element_map[cidr]

    def add_ip_to_ban_list_with_cidr(self, cidr, is_cidr_permanently_banned: int, ban_time: int = 0):
        """
        This function add cidr to bpf map

        Args:
            cidr (str): The cidr which will be added.
            is_cidr_permanently_banned (int): Just as the name, 0 is temporarily, 1 is permanently
            ban_time (int, optional): If choose temporarily banned, set this to the time(s) you prefer

        Returns:
            int: 1 if cidr exists, 0 if success, -1 if error
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            result = -1
            if network.version == 4:
                result = self.banlist_v4.add_cidr(cidr, is_cidr_permanently_banned, ban_time)
                if result == 0:
                    self.ipv4_cidr_map[self.banlist_v4.cidr_map[cidr]] = self.banlist_v4.element_map[cidr]
                    logging.info(f"CIDR: {cidr} have have been added")
            # if ipv6
            if network.version == 6:
               result = self.banlist_v6.add_cidr(cidr, is_cidr_permanently_banned, ban_time)
               if result == 0:
                    self.ipv6_cidr_map[self.banlist_v6.cidr_map[cidr]] = self.banlist_v6.element_map[cidr]
                    logging.info(f"CIDR: {cidr} have have been added")
            if result == 1:
                logging.info(f"CIDR: {cidr} have have been skipped for it has been existed")
            return result
        except Exception as e:
            logging.error(f"Failed to add CIDR: {cidr} to Map due to {e}")
            return -1

    def remove_ip_from_ban_list_with_cidr(self, cidr):
        try:
            print(self.banlist_v4.cidr_list, cidr)
            network = ipaddress.ip_network(cidr, strict=False)
            print(network.version)
            result = -1
            if network.version == 4:
                result = self.banlist_v4.check_cidr(cidr)
                if result == 0:
                    cidr_struct = self.banlist_v4.cidr_map[cidr]
                    result = self.banlist_v4.remove_cidr(cidr)
                    self.ipv4_cidr_map.pop(cidr_struct)
                    logging.info(f"CIDR: {cidr} have have been removed")
            # if ipv6
            if network.version == 6:
                result = self.banlist_v6.check_cidr(cidr)
                if result == 0:
                    cidr_struct = self.banlist_v6.cidr_map[cidr]
                    result = self.banlist_v6.remove_cidr(cidr_struct)
                    self.ipv6_cidr_map.pop(cidr_struct)
                    logging.info(f"CIDR: {cidr} have have been removed")
            if result == 1:
                logging.info(f"CIDR: {cidr} have have been skipped for it not exists")
            return result
        except Exception as e:
            logging.error(f"Failed to remove CIDR {str(cidr)} from Map due to {e}")
            return -1