from banner_map_module import BannedIpXdpMap
from banner_prog_module import BannedIpXdpProg
from associated_module import convert_u32_to_ip, in6_addr_to_ipv6
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import subprocess
import uvicorn
import atexit
import logging
import sys
# Gauge float, INFO string
from prometheus_client import Gauge, CollectorRegistry
from prometheus_client.exposition import generate_latest
import time, datetime

class InfoFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.INFO


class ErrorFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.ERROR


# 创建 logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# 创建处理器
info_handler = logging.StreamHandler(sys.stdout)
info_handler.setLevel(logging.INFO)
info_handler.addFilter(InfoFilter())

error_handler = logging.StreamHandler(sys.stderr)
error_handler.setLevel(logging.ERROR)
error_handler.addFilter(ErrorFilter())

# 创建格式化器
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 将格式化器添加到处理器
info_handler.setFormatter(formatter)
error_handler.setFormatter(formatter)

# 将处理器添加到 logger
logger.addHandler(info_handler)
logger.addHandler(error_handler)

# XDP_VAR_INIT
v4_banned_list_location = '/etc/nginx/banned_ipv4'
v4_banned_list_persistence = '/etc/nginx/banned_ipv4_persistence'
v6_banned_list_location = '/etc/nginx/banned_ipv6'
v6_banned_list_persistence = '/etc/nginx/banned_ipv6_persistence'
prog_location = './mirrors_banner.c'
prog_func_name = 'mirrors_banner'

# XDP_INIT
xdp_map = BannedIpXdpMap(v4_banned_list_location, v6_banned_list_location, v4_banned_list_persistence, v6_banned_list_persistence)
xdp_prog = BannedIpXdpProg(prog_location, prog_func_name)

# DEV_INIT_LIST
init_dict = {
    'eno1': 1,
    'eno2': 1,
    'eno3': 1,
    'eno4': 1,
    'enp8s0': 1
}

# 创建 Prometheus 指标注册表
registry = CollectorRegistry()

# 创建 Gauge 指标
ipv4_banned_access_times = Gauge(
    'ipv4_banned_access_times',
    'Access times of each banned IPv4 address',
    ['ip'],
    registry=registry
)
ipv4_banned_last_access_time = Gauge(
    'ipv4_banned_last_access_time',
    'Last access time of each banned IPv4 address',
    ['ip'],
    registry=registry
)

ipv6_banned_access_times = Gauge(
    'ipv6_banned_access_times',
    'Access times of each banned IPv6 address',
    ['ip'],
    registry=registry
)
ipv6_banned_last_access_time = Gauge(
    'ipv6_banned_last_access_time',
    'Last access time of each banned IPv6 address',
    ['ip'],
    registry=registry
)

def get_system_boot_time():
    # 读取 /proc/stat 文件获取 btime (系统启动时间)
    with open('/proc/stat', 'r') as f:
        for line in f:
            if line.startswith('btime'):
                btime = int(line.strip().split()[1])
                return btime
    raise RuntimeError('Failed to get system boot time.')

def convert_ktime_to_time(ktime_ns):
    # 获取系统启动时间
    boot_time = get_system_boot_time()

    # 将纳秒转换为毫秒(Grafana Time 以毫秒为单位)
    ktime_sec = ktime_ns / 1e9

    # 计算当前时间戳
    return (boot_time + ktime_sec)*1000


# 更新指标
def update_metrics(ipv4_map, ipv6_map):

    for ip, info in ipv4_map.items():
        ipv4_banned_access_times.labels(ip=convert_u32_to_ip(ip)).set(info.access_times)
        ipv4_banned_last_access_time.labels(ip=convert_u32_to_ip(ip)).set(convert_ktime_to_time(info.timestamp))

    for ip, info in ipv6_map.items():
        ipv6_banned_access_times.labels(ip=in6_addr_to_ipv6(ip.in6_u.u6_addr8)).set(info.access_times)
        ipv6_banned_last_access_time.labels(ip=in6_addr_to_ipv6(ip.in6_u.u6_addr8)).set(convert_ktime_to_time(info.timestamp))


# FASTAPI_INIT
app = FastAPI()


@app.get("/detach")
def remove(device: str, attach_type: int):
    err = xdp_prog.remove_xdp_prog(net_device=device, attach_type=attach_type)
    if err:
        init_dict[device] = None
        logging.info(f"xdp_rule have been removed from {device} with type {attach_type}")
        return {"message": f"xdp_rule have been removed from {device} with type {attach_type}"}
    return {"message": f"xdp_rule failed to be removed from {device} with type {attach_type}"}


@app.get("/attach")
def attach(device: str, attach_type: int):
    err = xdp_prog.attach_xdp_prog(net_device=device, attach_type=attach_type)
    if err:
        init_dict[device] = attach_type
        logging.info(f"xdp_rule have been attached to {device} with type {attach_type}")
        return {"message": f"xdp_rule have been attached to {device} with type {attach_type}"}
    return {"message": f"xdp_rule failed to be attached to {device} with type {attach_type}"}


@app.get("/status")
def status():
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        output = result.stdout

        xdp_states = {}
        current_interface = None
        xdp_info = None

        for line in output.split('\n'):
            if not line.strip():
                continue

            if line.startswith(' '):
                if 'prog/xdp' in line:
                    xdp_prog_name = line.split(' ')[4]
                    xdp_info = f'attached | {xdp_prog_name}'
            else:
                if current_interface:
                    xdp_states[current_interface] = xdp_info if xdp_info else 'detached'

                current_interface = line.split(':', 2)[1].strip()
                xdp_info = None

        return {"message": f"{xdp_states}"}

    except Exception as e:
        logging.error(f"Error checking XDP attach states: {e}")
        return {"message": f"Error checking XDP attach states: {e}"}


@app.get("/update")
def update(cidr: str, ban_type: int=0, ban_time: int=0):
    err = xdp_map.add_ip_to_ban_list_with_cidr(cidr=cidr, is_cidr_permanently_banned=ban_type, ban_time=ban_time)
    if err == 0:
        return {"message":f"Successfully added {cidr} to banned list"}
    if err == 1:
        return {"message": f"{cidr} exists, skip"}
    if err == -1:
        return {"message": f"Failed to add {cidr} to banned list"}


@app.get("/remove")
def remove(cidr: str):
    err = xdp_map.remove_ip_from_ban_list_with_cidr(cidr=cidr)
    if err == 0:
        return {"message":f"Successfully removed {cidr} from banned list"}
    if err == 1:
        return {"message": f"{cidr} not exists, skip"}
    if err == -1:
        return {"message": f"Failed to add {cidr} to banned list"}


@app.get("/reload")
def reload():
    try:
        xdp_map.load_banned_list_file()
        logging.info("Successfully reloaded banned list")
        return {"message":"Successfully reloaded banned list"}
    except Exception as e:
        logging.error(f"XDP reload failed: {e}")
        return {"message": "XDP reload failed"}


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    update_metrics(xdp_map.ipv4_access_map, xdp_map.ipv6_access_map)
    return generate_latest(registry)


def cleanup():
    for device, attach_type in init_dict.items():
        if attach_type is not None:
            xdp_prog.remove_xdp_prog(net_device=device, attach_type=attach_type)
            logging.info(f"XDP program detached from {device} with attach type {attach_type}")


# Register exit func
atexit.register(cleanup)

if __name__ == "__main__":
    for item in init_dict.items():
        xdp_prog.attach_xdp_prog(item[0], item[1])
        logging.info(f"XDP program attached to {item[0]} with attach type {item[1]}")
    uvicorn.run(app=app, host="198.18.114.2", port=8080)
