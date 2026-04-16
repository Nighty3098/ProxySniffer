import random
import socket
from typing import List, Tuple


def get_free_port(start: int = 15000, end: int = 60000) -> int:
    while True:
        port = random.randint(start, end)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", port))
            sock.close()
            return port
        except OSError:
            continue
