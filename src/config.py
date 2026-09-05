import os
from multiprocessing import cpu_count

CPU_CORES = cpu_count()
DEFAULT_WORKERS = max(8, CPU_CORES * 2)

SINGBOX_PATH = "/tmp/sing-box-1.13.4-linux-amd64/sing-box"
SINGBOX_INSTALLED = os.path.exists(SINGBOX_PATH)
TEST_URLS = [
    "http://www.gstatic.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.apple.com/library/test/success.html",
]
SINGBOX_POOL_SIZE = max(4, CPU_CORES)
TCP_PRECHECK_TIMEOUT = 1.5

proxy_mapping = {
    1: "HTTP",
    2: "HTTPS",
    3: "SOCKS4",
    4: "SOCKS5",
    5: "MTPROTO",
    6: "HYSTERIA2",
    7: "SHADOW_SOCKS",
    8: "TROJAN",
    9: "VMESS",
    10: "VLESS",
}

PROTOCOLS = list(proxy_mapping.values())

DEFAULT_LIMITS = {
    "HTTP": 2000,
    "HTTPS": 2000,
    "SOCKS4": 2000,
    "SOCKS5": 2000,
    "MTPROTO": 500,
    "HYSTERIA2": 500,
    "SHADOW_SOCKS": 500,
    "TROJAN": 500,
    "VMESS": 500,
    "VLESS": 500,
}


def get_proxy_sources():
    from links import (
        proxy_HTTP,
        proxy_HTTPS,
        proxy_HYSTERIA2,
        proxy_MTPROTO,
        proxy_SHADOW_SOCKS,
        proxy_SOCKS4,
        proxy_SOCKS5,
        proxy_TROJAN,
        proxy_VLESS,
        proxy_VMESS,
    )

    return {
        "HTTP": proxy_HTTP,
        "HTTPS": proxy_HTTPS,
        "SOCKS4": proxy_SOCKS4,
        "SOCKS5": proxy_SOCKS5,
        "MTPROTO": proxy_MTPROTO,
        "HYSTERIA2": proxy_HYSTERIA2,
        "SHADOW_SOCKS": proxy_SHADOW_SOCKS,
        "TROJAN": proxy_TROJAN,
        "VMESS": proxy_VMESS,
        "VLESS": proxy_VLESS,
    }
