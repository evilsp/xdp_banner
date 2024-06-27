from bcc import BPF
import logging

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