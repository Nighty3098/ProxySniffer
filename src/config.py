import os
from multiprocessing import cpu_count

CPU_CORES = cpu_count()
DEFAULT_WORKERS = max(8, CPU_CORES * 2)

SINGBOX_PATH = "/tmp/sing-box-1.13.4-linux-amd64/sing-box"
SINGBOX_INSTALLED = os.path.exists(SINGBOX_PATH)

TOR_BUNDLE_VERSION = "15.0.23"
TOR_BUNDLE_DIR = f"/tmp/tor-expert-bundle-{TOR_BUNDLE_VERSION}-linux-x86_64"
TOR_PATH = os.path.join(TOR_BUNDLE_DIR, "tor-client")
LYREBIRD_PATH = os.path.join(TOR_BUNDLE_DIR, "tor", "pluggable_transports", "lyrebird")
TOR_INSTALLED = os.path.exists(TOR_PATH) and os.access(TOR_PATH, os.X_OK)
LYREBIRD_INSTALLED = os.path.exists(LYREBIRD_PATH) and os.access(LYREBIRD_PATH, os.X_OK)
TOR_BRIDGE_PROTOCOLS = ["TOR_OBFS4", "TOR_WEBTUNNEL", "TOR_SNOWFLAKE"]
SNOWFLAKE_VERSION = "2.14.1"
SNOWFLAKE_BUNDLE_PATH = (
    f"/tmp/snowflake-{SNOWFLAKE_VERSION}-linux-x86_64/snowflake-client"
)


def _find_snowflake_client() -> str:
    for candidate in ("/usr/bin/snowflake-client", SNOWFLAKE_BUNDLE_PATH):
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return SNOWFLAKE_BUNDLE_PATH


SNOWFLAKE_CLIENT_PATH = _find_snowflake_client()
SNOWFLAKE_CLIENT_INSTALLED = os.path.exists(SNOWFLAKE_CLIENT_PATH) and os.access(
    SNOWFLAKE_CLIENT_PATH, os.X_OK
)
TOR_BOOTSTRAP_TIMEOUT = 90
TOR_CHECK_PORTS_START = 25000
TOR_MAX_CONCURRENT = 4
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
    11: "TOR_OBFS4",
    12: "TOR_WEBTUNNEL",
    13: "TOR_SNOWFLAKE",
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
    "TOR_OBFS4": 100,
    "TOR_WEBTUNNEL": 100,
    "TOR_SNOWFLAKE": 100,
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
        proxy_TOR_obfs4,
        proxy_TOR_snowflake,
        proxy_TOR_webtunnel,
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
        "TOR_OBFS4": proxy_TOR_obfs4,
        "TOR_WEBTUNNEL": proxy_TOR_webtunnel,
        "TOR_SNOWFLAKE": proxy_TOR_snowflake,
    }
