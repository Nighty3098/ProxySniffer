import socket
from itertools import count

PROXY_PREFIXES = (
    "http://",
    "https://",
    "socks4://",
    "socks5://",
    "socks4h://",
    "socks5h://",
    "hysteria2://",
    "ss://",
    "trojan://",
    "vmess://",
    "vless://",
    "snowflake",
    "obfs4",
    "webtunnel",
)

_port_counter = count(1)


def get_free_port(start: int = 15000, end: int = 60000) -> int:
    span = end - start
    for _ in range(span):
        port = start + (next(_port_counter) % span)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sock.settimeout(0.1)
                return port
        except OSError:
            continue
    raise RuntimeError("no free ports available")
