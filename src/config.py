import os
from multiprocessing import cpu_count

CPU_CORES = cpu_count()
DEFAULT_WORKERS = max(8, CPU_CORES * 2)

SINGBOX_PATH = "/tmp/sing-box-1.13.4-linux-amd64/sing-box"
SINGBOX_INSTALLED = os.path.exists(SINGBOX_PATH)
TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.apple.com/library/test/success.html",
]
SINGBOX_POOL_SIZE = max(4, CPU_CORES)

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
