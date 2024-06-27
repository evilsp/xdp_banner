from ctypes import CDLL, Structure, c_char, c_char_p, c_int, c_uint8, POINTER, create_string_buffer


class CIDR(Structure):
    _fields_ = [
        ("version", c_int),
        ("addr", c_uint8 * 16),
        ("mask", c_uint8 * 16),
        ("proto", c_int),
    ]

libcidr_module = CDLL('/usr/local/lib/libcidr.so')

# CIDR * cidr_from_str(const char *addr)
libcidr_module.cidr_from_str.restype = POINTER(CIDR)
libcidr_module.cidr_from_str.argtypes = [POINTER(c_char)]

# char * cidr_to_str(const CIDR *block, int flags)

# Represents the C char * datatype when it points to a zero-terminated string.
# For a general character pointer that may also point to binary data, POINTER(c_char) must be used.
# The constructor accepts an integer address, or a bytes object.
libcidr_module.cidr_to_str.restype = c_char_p
libcidr_module.cidr_to_str.argtypes = [POINTER(CIDR), c_int]

def str_to_cidr(cidr_str: str):
    # Transfer Python str to c_char_p
    ip_c_str = create_string_buffer(cidr_str.encode('utf-8'))
    cidr_ptr = libcidr_module.cidr_from_str(ip_c_str)
    # Get struct cidr
    if cidr_ptr:
        # &
        cidr = cidr_ptr.contents
        return cidr
    else:
        return None

def cidr_to_str(cidr_struct: CIDR, flags: int = 0):

    cidr_str_bytes = libcidr_module.cidr_to_str(cidr_struct, flags)
    if not cidr_str_bytes:
        raise ValueError("Failed to convert CIDR structure to string")
    cidr_str = cidr_str_bytes.decode('utf-8')
    return cidr_str

# cidr_str = "192.168.1.0/24"
# cidr_struct = str_to_cidr(cidr_str)
# if cidr_struct is not None:
#     print("CIDR structure created from string:", ".".join(map(str, cidr_struct.addr)))
#
#     converted_cidr_str = cidr_to_str(cidr_struct)
#     print("CIDR string converted back from structure:", converted_cidr_str)
# else:
#     print("Failed to convert CIDR string to structure")

