import asyncio
import json
import os
import tempfile
import time
from typing import Dict, List, Tuple

import aiohttp

from config import SINGBOX_INSTALLED, SINGBOX_PATH, SINGBOX_POOL_SIZE, TEST_URLS
from parsers import (
    parse_hysteria2_link,
    parse_shadowsocks_link,
    parse_trojan_link,
    parse_vless_link,
    parse_vmess_link,
)
from utils import get_free_port


def generate_singbox_config(proxy_link: str, proxy_type: str) -> dict | None:
    try:
        config = {
            "log": {"level": "error"},
            "dns": {
                "independent_cache": True,
                "servers": [
                    {"address": "8.8.8.8"},
                    {"address": "1.1.1.1"},
                ],
            },
            "inbounds": [{"tag": "mixed-in", "type": "mixed", "listen_port": 1080}],
            "outbounds": [],
        }

        if proxy_type.upper() == "SHADOW_SOCKS":
            ss_data = parse_shadowsocks_link(proxy_link)
            if not ss_data:
                return None

            ss_outbound = {
                "tag": "proxy",
                "type": "shadowsocks",
                "server": ss_data["server"],
                "server_port": ss_data["port"],
                "method": ss_data.get("method", "aes-256-gcm"),
                "password": ss_data["password"],
            }

            plugin = ss_data.get("plugin")
            if plugin:
                if plugin.startswith("obfs"):
                    ss_outbound["plugin"] = {"type": "obfs", "conf": {}}
                    if "obfs=http" in plugin:
                        ss_outbound["plugin"]["conf"]["mode"] = "http"
                    elif "obfs=tls" in plugin:
                        ss_outbound["plugin"]["conf"]["mode"] = "tls"
                elif "v2ray-plugin" in plugin:
                    ss_outbound["plugin"] = {"type": "v2ray-plugin", "conf": {}}

            config["outbounds"].append(ss_outbound)

        elif proxy_type.upper() == "TROJAN":
            tr_data = parse_trojan_link(proxy_link)
            if not tr_data:
                return None
            outbound = {
                "tag": "proxy",
                "type": "trojan",
                "server": tr_data["server"],
                "server_port": tr_data["port"],
                "password": tr_data["password"],
            }

            net_type = tr_data.get("type", "tcp")

            if net_type == "ws":
                outbound["transport"] = {"type": "ws", "path": tr_data.get("path", "/")}
                if tr_data.get("host"):
                    outbound["transport"]["headers"] = {"Host": tr_data["host"]}
            elif net_type == "http":
                outbound["transport"] = {
                    "type": "http",
                    "path": tr_data.get("path", "/"),
                }
                if tr_data.get("host"):
                    outbound["transport"]["headers"] = {"Host": tr_data["host"]}
            elif net_type == "httpupgrade":
                outbound["transport"] = {
                    "type": "httpupgrade",
                    "path": tr_data.get("path", "/"),
                }
                if tr_data.get("host"):
                    outbound["transport"]["headers"] = {"Host": tr_data["host"]}
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": tr_data.get("serviceName", ""),
                }
                if tr_data.get("mode"):
                    outbound["transport"]["multiplex"] = {"enabled": True}

            security = tr_data.get("security", "")
            if security == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "insecure": tr_data.get("insecure", "0") == "1"
                    or tr_data.get("allowInsecure", "0") == "1",
                }
                if tr_data.get("sni"):
                    outbound["tls"]["server_name"] = tr_data["sni"]
                if tr_data.get("fp"):
                    outbound["tls"]["utls"] = {
                        "enabled": True,
                        "fingerprint": tr_data["fp"],
                    }
                if tr_data.get("alpn"):
                    outbound["tls"]["alpn"] = tr_data["alpn"].split(",")

            config["outbounds"].append(outbound)

        elif proxy_type.upper() == "VMESS":
            vm_data = parse_vmess_link(proxy_link)
            if not vm_data:
                return None
            outbound = {
                "tag": "proxy",
                "type": "vmess",
                "server": vm_data["server"],
                "server_port": vm_data["port"],
                "uuid": vm_data["id"],
                "alterID": vm_data.get("aid", 0),
            }

            net_type = vm_data.get("net", "tcp")
            path = vm_data.get("path", "")

            if net_type == "ws":
                outbound["transport"] = {"type": "ws", "path": path}
                if vm_data.get("host"):
                    outbound["transport"]["headers"] = {"Host": vm_data["host"]}
            elif net_type == "httpupgrade":
                outbound["transport"] = {"type": "httpupgrade", "path": path}
                if vm_data.get("host"):
                    outbound["transport"]["headers"] = {"Host": vm_data["host"]}
            elif net_type == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": path}
            elif net_type == "h2" or net_type == "http":
                outbound["transport"] = {"type": "http", "path": path}

            if vm_data.get("tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "insecure": vm_data.get("insecure", "0") == "1"
                    or vm_data.get("allowInsecure", "0") == "1",
                }
                if vm_data.get("sni"):
                    outbound["tls"]["server_name"] = vm_data["sni"]
                if vm_data.get("fp"):
                    outbound["tls"]["utls"] = {
                        "enabled": True,
                        "fingerprint": vm_data["fp"],
                    }

            config["outbounds"].append(outbound)

        elif proxy_type.upper() == "VLESS":
            vl_data = parse_vless_link(proxy_link)
            if not vl_data:
                return None
            outbound = {
                "tag": "proxy",
                "type": "vless",
                "server": vl_data["server"],
                "server_port": vl_data["port"],
                "uuid": vl_data["id"],
            }

            security = vl_data.get("security", "none")
            net_type = vl_data.get("type", "tcp")
            path = vl_data.get("path", "")
            flow = vl_data.get("flow", "")

            if net_type == "ws":
                outbound["transport"] = {"type": "ws", "path": path}
                if vl_data.get("host"):
                    outbound["transport"]["headers"] = {"Host": vl_data["host"]}
            elif net_type == "httpupgrade":
                outbound["transport"] = {"type": "httpupgrade", "path": path}
                if vl_data.get("host"):
                    outbound["transport"]["headers"] = {"Host": vl_data["host"]}
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": path or vl_data.get("serviceName", ""),
                }
                if vl_data.get("mode") == "gun":
                    outbound["transport"]["multiplex"] = {"enabled": True}
            elif net_type == "h2":
                outbound["transport"] = {"type": "http", "path": path}

            if security == "reality":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": vl_data.get("sni", "www.apple.com"),
                    "reality": {
                        "public_key": vl_data.get("pbk", ""),
                        "short_id": vl_data.get("sid", ""),
                    },
                }
                if vl_data.get("fp"):
                    outbound["tls"]["utls"] = {
                        "enabled": True,
                        "fingerprint": vl_data["fp"],
                    }
                if flow and flow not in ["", "none"]:
                    outbound["flow"] = flow
            elif security == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "insecure": vl_data.get("insecure", "0") == "1"
                    or vl_data.get("allowInsecure", "0") == "1",
                }
                if vl_data.get("sni"):
                    outbound["tls"]["server_name"] = vl_data["sni"]
                if vl_data.get("fp"):
                    outbound["tls"]["utls"] = {
                        "enabled": True,
                        "fingerprint": vl_data["fp"],
                    }
                if flow:
                    outbound["flow"] = flow

            config["outbounds"].append(outbound)

        elif proxy_type.upper() == "HYSTERIA2":
            hy_data = parse_hysteria2_link(proxy_link)
            if not hy_data:
                return None

            hy_outbound = {
                "tag": "proxy",
                "type": "hysteria2",
                "server": hy_data["server"],
                "server_port": hy_data["port"],
                "password": hy_data["password"],
            }

            if hy_data.get("insecure") == "1":
                hy_outbound["tls"] = {"enabled": True, "insecure": True}
            if hy_data.get("sni"):
                if "tls" not in hy_outbound:
                    hy_outbound["tls"] = {"enabled": True}
                hy_outbound["tls"]["server_name"] = hy_data["sni"]
            if hy_data.get("fp"):
                if "tls" not in hy_outbound:
                    hy_outbound["tls"] = {"enabled": True}
                hy_outbound["tls"] = hy_outbound.get("tls", {})
                hy_outbound["tls"]["utls"] = {
                    "enabled": True,
                    "fingerprint": hy_data["fp"],
                }

            config["outbounds"].append(hy_outbound)

        else:
            return None

        config["outbounds"].append({"tag": "direct", "type": "direct"})

        return config
    except:
        return None


async def _check_singbox_async(
    proxy_link: str, proxy_type: str, port: int, timeout: int
) -> Tuple[str, str, bool, float]:
    if not SINGBOX_INSTALLED:
        return proxy_link, proxy_type, False, 0.0

    config = generate_singbox_config(proxy_link, proxy_type)
    if not config:
        return proxy_link, proxy_type, False, 0.0

    config["inbounds"][0]["listen_port"] = port

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    proc = None
    try:
        start = time.time()

        proc = await asyncio.create_subprocess_exec(
            SINGBOX_PATH,
            "run",
            "-c",
            config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        for _ in range(timeout * 2):
            await asyncio.sleep(0.5)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), timeout=1
                )
                writer.close()
                await writer.wait_closed()

                for test_url in TEST_URLS:
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                test_url,
                                proxy=f"http://127.0.0.1:{port}",
                                timeout=aiohttp.ClientTimeout(total=8),
                                ssl=False,
                            ) as resp:
                                if resp.status in [200, 204, 201, 301, 302]:
                                    speed = round((time.time() - start) * 1000, 1)
                                    proc.terminate()
                                    try:
                                        await asyncio.wait_for(proc.wait(), timeout=2)
                                    except:
                                        proc.kill()
                                    return proxy_link, proxy_type, True, speed
                    except:
                        continue
            except:
                pass

        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except:
            proc.kill()
        return proxy_link, proxy_type, False, 0.0

    except Exception:
        if proc:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2)
            except:
                proc.kill()
        return proxy_link, proxy_type, False, 0.0
    finally:
        try:
            os.unlink(config_path)
        except:
            pass


async def check_with_singbox(
    proxy_link: str, proxy_type: str, timeout: int = 10
) -> Tuple[bool, float]:
    port = get_free_port()
    try:
        result = await asyncio.wait_for(
            _check_singbox_async(proxy_link, proxy_type, port, timeout),
            timeout=timeout + 5,
        )
        return result[2], result[3]
    except asyncio.TimeoutError:
        return False, 0.0
    except Exception:
        return False, 0.0


async def check_mtproto_tcp(server: str, port: int, timeout: int) -> Tuple[bool, float]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True, 0
    except:
        return False, 0


async def check_mtproto_handshake(
    server: str, port: int, secret: str, timeout: int
) -> Tuple[bool, float]:
    try:
        secret_hex = secret
        is_obfuscated2 = secret.startswith("ee")

        if is_obfuscated2 and len(secret) >= 34:
            secret_hex = secret[2:34]

        secret_bytes = (
            bytes.fromhex(secret_hex) if len(secret_hex) % 2 == 0 else secret.encode()
        )

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )

        try:
            writer.write(secret_bytes)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)

            if len(data) > 0:
                writer.close()
                await writer.wait_closed()
                return True, 1
        except:
            pass

        writer.close()
        await writer.wait_closed()
        return False, 0
    except:
        return False, 0


async def check_mtproto_http(
    server: str, port: int, secret: str, timeout: int
) -> Tuple[bool, float]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )

        http_request = b"GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n"

        try:
            writer.write(http_request)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=timeout)

            writer.close()
            await writer.wait_closed()

            if data and (b"HTTP" in data or len(data) > 0):
                return True, 1
        except:
            pass

        writer.close()
        await writer.wait_closed()
        return False, 0
    except:
        return False, 0


async def check_mtproto_all_methods(
    server: str, port: int, secret: str, timeout: int
) -> Tuple[bool, float]:
    start = time.time()

    ok, _ = await check_mtproto_tcp(server, port, timeout)
    if not ok:
        ok, _ = await check_mtproto_handshake(server, port, secret, timeout)
    if not ok:
        ok, _ = await check_mtproto_http(server, port, secret, timeout)

    if ok:
        speed = round((time.time() - start) * 1000, 1)
        return True, speed
    return False, 0.0


async def check_hysteria2(server: str, port: int, timeout: int) -> Tuple[bool, float]:
    try:
        start = time.time()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        speed = round((time.time() - start) * 1000, 1)
        return True, speed
    except:
        return False, 0.0


async def check_shadowsocks(server: str, port: int, timeout: int) -> Tuple[bool, float]:
    try:
        start = time.time()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )

        try:
            writer.write(b"\x00")
            await writer.drain()
            await asyncio.wait_for(reader.read(1), timeout=timeout)
        except:
            pass

        writer.close()
        await writer.wait_closed()
        speed = round((time.time() - start) * 1000, 1)
        return True, speed
    except:
        return False, 0.0


async def check_trojan(server: str, port: int, timeout: int) -> Tuple[bool, float]:
    try:
        start = time.time()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        speed = round((time.time() - start) * 1000, 1)
        return True, speed
    except:
        return False, 0.0


async def check_vmess(vm_data: Dict, timeout: int) -> Tuple[bool, float]:
    try:
        start = time.time()
        server = vm_data["server"]
        port = vm_data["port"]
        net = vm_data.get("net", "tcp")
        path = vm_data.get("path", "/")

        if net == "ws":
            import ssl

            ctx = ssl.create_default_context() if vm_data.get("tls") == "tls" else None

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port, ssl=ctx), timeout=timeout
            )

            ws_request = f"GET {path} HTTP/1.1\r\nHost: {server}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode()
            writer.write(ws_request)
            await writer.drain()

            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                if b"101" in response or b"HTTP" in response:
                    writer.close()
                    await writer.wait_closed()
                    speed = round((time.time() - start) * 1000, 1)
                    return True, speed
            except:
                pass

            writer.close()
            await writer.wait_closed()
            return False, 0.0
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port), timeout=timeout
            )

            if vm_data.get("tls") == "tls":
                import ssl

                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(server, port, ssl=ctx), timeout=timeout
                )

            writer.close()
            await writer.wait_closed()
            speed = round((time.time() - start) * 1000, 1)
            return True, speed
    except:
        return False, 0.0


async def check_vless(vl_data: Dict, timeout: int) -> Tuple[bool, float]:
    try:
        start = time.time()
        server = vl_data["server"]
        port = vl_data["port"]
        security = vl_data.get("security", "none")
        net_type = vl_data.get("type", "tcp")

        if security in ["tls", "reality"] or net_type == "tcp":
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port), timeout=timeout
            )

        writer.close()
        await writer.wait_closed()
        speed = round((time.time() - start) * 1000, 1)
        return True, speed
    except:
        return False, 0.0


async def check_hysteria2_full(hy_data: Dict, timeout: int) -> Tuple[bool, float]:
    try:
        start = time.time()
        server = hy_data["server"]
        port = hy_data["port"]

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )

        writer.close()
        await writer.wait_closed()
        speed = round((time.time() - start) * 1000, 1)
        return True, speed
    except:
        return False, 0.0
