import asyncio
import json
import os
import shutil
import tempfile
import time
from typing import Dict, List, Tuple

import aiohttp

from config import (
    LYREBIRD_INSTALLED,
    LYREBIRD_PATH,
    SINGBOX_INSTALLED,
    SINGBOX_PATH,
    SINGBOX_REQUEST_TIMEOUT,
    SINGBOX_STARTUP_TIMEOUT,
    SINGBOX_TEST_URLS,
    SNOWFLAKE_CLIENT_INSTALLED,
    SNOWFLAKE_CLIENT_PATH,
    TCP_PRECHECK_TIMEOUT,
    TOR_BOOTSTRAP_TIMEOUT,
    TOR_CHECK_PORTS_START,
    TOR_INSTALLED,
    TOR_PATH,
)
from parsers import (
    parse_bridge_line,
    parse_hysteria2_link,
    parse_shadowsocks_link,
    parse_trojan_link,
    parse_vless_link,
    parse_vmess_link,
    strip_bridge_prefix,
)
from utils import get_free_port


async def tcp_precheck(
    server: str, port: int, timeout: float = TCP_PRECHECK_TIMEOUT
) -> Tuple[bool, float]:
    try:
        start = time.time()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=timeout
        )
        latency = round((time.time() - start) * 1000, 1)
        writer.close()
        await writer.wait_closed()
        return True, latency
    except Exception:
        return False, 0.0


def _is_true(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _build_vless_outbound(vl_data: Dict) -> dict | None:
    """Build a sing-box VLESS outbound from parsed link data.

    Returns None for links whose parameters cannot be reproduced by sing-box
    (KCP/XHTTP/raw HTTP header obfuscation, broken REALITY, encrypted VLESS).
    Such links are reported as not working instead of producing false
    positives from a bare TCP/TLS reachability test.
    """
    security = (vl_data.get("security") or "none").lower()
    net_type = (vl_data.get("type") or "tcp").lower()
    header_type = (vl_data.get("headerType") or "none").lower()
    flow = vl_data.get("flow") or ""

    if security not in ("", "none", "tls", "reality"):
        return None
    if (vl_data.get("encryption") or "none").lower() not in ("", "none"):
        return None
    if net_type in ("kcp", "mkcp", "xhttp", "splithttp", "http3"):
        return None
    if net_type == "tcp" and header_type not in ("", "none"):
        return None

    outbound = {
        "tag": "proxy",
        "type": "vless",
        "server": vl_data["server"],
        "server_port": int(vl_data["port"]),
        "uuid": vl_data["id"],
    }

    path = vl_data.get("path") or "/"
    host = vl_data.get("host") or ""

    if security == "none" and flow and net_type == "tcp":
        # flow (vision) only makes sense over TLS, such a link is broken.
        return None
    if flow and net_type != "tcp":
        flow = ""
    if flow and flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
        return None

    if net_type == "ws":
        outbound["transport"] = {"type": "ws", "path": path}
        if host:
            outbound["transport"]["headers"] = {"Host": host}
    elif net_type == "httpupgrade":
        outbound["transport"] = {"type": "httpupgrade", "path": path}
        if host:
            outbound["transport"]["headers"] = {"Host": host}
    elif net_type == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": vl_data.get("serviceName") or path.lstrip("/"),
        }
    elif net_type in ("http", "h2"):
        transport = {"type": "http", "path": path}
        hosts = [h.strip() for h in host.split(",") if h.strip()]
        if hosts:
            transport["host"] = hosts
        outbound["transport"] = transport
    elif net_type == "quic":
        outbound["transport"] = {"type": "quic"}
    elif net_type != "tcp":
        return None

    if security == "reality":
        public_key = vl_data.get("pbk") or ""
        if not public_key:
            return None
        outbound["tls"] = {
            "enabled": True,
            "server_name": vl_data.get("sni") or host or vl_data["server"],
            "utls": {
                "enabled": True,
                "fingerprint": vl_data.get("fp") or "chrome",
            },
            "reality": {
                "enabled": True,
                "public_key": public_key,
                "short_id": vl_data.get("sid") or "",
            },
        }
    elif security == "tls":
        tls = {
            "enabled": True,
            "insecure": _is_true(vl_data.get("insecure"))
            or _is_true(vl_data.get("allowInsecure")),
        }
        server_name = vl_data.get("sni") or host
        if server_name:
            tls["server_name"] = server_name
        if vl_data.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": vl_data["fp"]}
        outbound["tls"] = tls

    alpn = (vl_data.get("alpn") or "").strip()
    if alpn and "tls" in outbound:
        alpn_list = [a.strip() for a in alpn.split(",") if a.strip()]
        if alpn_list:
            outbound["tls"]["alpn"] = alpn_list

    if flow:
        outbound["flow"] = flow

    packet_encoding = (vl_data.get("packetEncoding") or "").lower()
    if packet_encoding in ("xudp", "packetaddr"):
        outbound["packet_encoding"] = packet_encoding

    return outbound


def generate_singbox_config(proxy_link: str, proxy_type: str) -> dict | None:
    try:
        config = {
            "log": {"level": "error"},
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
                "alter_id": vm_data.get("aid", 0),
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
            outbound = _build_vless_outbound(vl_data)
            if not outbound:
                return None

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


def generate_singbox_config_trimmed(proxy_link: str, proxy_type: str) -> dict | None:
    config = generate_singbox_config(proxy_link, proxy_type)
    if not config:
        return None

    # "level": "none" is rejected by sing-box >= 1.14 and legacy dns.servers
    # entries are removed there; a bare config runs on both 1.13 and 1.14+.
    config["log"] = {"disabled": True}
    config.pop("dns", None)
    config["inbounds"] = [{"tag": "mixed-in", "type": "mixed", "listen_port": 1080}]

    for outbound in config.get("outbounds", []):
        outbound.pop("mux", None)

    return config


async def _wait_for_listener(proc, port: int, timeout: float) -> bool:
    """Wait until sing-box listens on `port` or exits (bad config, dead server)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            return False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=0.25
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.05)
    return False


async def _stop_process(proc) -> None:
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=2)
    except Exception:
        try:
            proc.kill()
            await asyncio.wait_for(proc.wait(), timeout=1)
        except Exception:
            pass


# Protocols whose endpoint listens on TCP can be filtered by a quick TCP
# connect. Hysteria2 is QUIC/UDP only: a TCP connect to its port usually
# fails even on a healthy server, so it is never prechecked this way.
TCP_PRECHECK_TYPES = ("VLESS", "VMESS", "TROJAN", "SHADOW_SOCKS")

_LINK_PARSERS = {
    "VLESS": parse_vless_link,
    "VMESS": parse_vmess_link,
    "TROJAN": parse_trojan_link,
    "HYSTERIA2": parse_hysteria2_link,
    "SHADOW_SOCKS": parse_shadowsocks_link,
}


def get_link_server(
    proxy_link: str, proxy_type: str
) -> Tuple[str | None, int | None]:
    """Extract (server, port) from a share link for the TCP precheck.

    Returns (None, None) when the link cannot be parsed.
    """
    parser = _LINK_PARSERS.get(proxy_type.upper())
    if parser is None:
        return None, None
    data = parser(proxy_link)
    if not data:
        return None, None
    server, port = data.get("server"), data.get("port")
    if not server or not port:
        return None, None
    try:
        return server, int(port)
    except (TypeError, ValueError):
        return None, None


async def _check_singbox_async(
    proxy_link: str,
    proxy_type: str,
    port: int,
    timeout: int,
    skip_precheck: bool = False,
) -> Tuple[str, str, bool, float]:
    if not SINGBOX_INSTALLED:
        return proxy_link, proxy_type, False, 0.0

    # TCP precheck is only a fast filter for unreachable hosts, never a
    # proof that the proxy works: reachable TCP ports are very common on
    # dead/shared endpoints. The parallel engine runs the precheck as a
    # separate mass phase (core.run_checks) and passes skip_precheck=True.
    if not skip_precheck and proxy_type.upper() in TCP_PRECHECK_TYPES:
        server_host, server_port = get_link_server(proxy_link, proxy_type)
        if server_host and server_port:
            try:
                pre_ok, _ = await tcp_precheck(server_host, server_port)
            except Exception:
                pre_ok = False
            if not pre_ok:
                return proxy_link, proxy_type, False, 0.0

    config = generate_singbox_config_trimmed(proxy_link, proxy_type)
    if not config:
        return proxy_link, proxy_type, False, 0.0

    config["inbounds"][0]["listen_port"] = port

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        config_path = f.name

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            SINGBOX_PATH,
            "run",
            "-c",
            config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        start = time.monotonic()
        if not await _wait_for_listener(proc, port, SINGBOX_STARTUP_TIMEOUT):
            return proxy_link, proxy_type, False, 0.0

        deadline = start + max(timeout, 2)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(
                total=SINGBOX_REQUEST_TIMEOUT, connect=SINGBOX_REQUEST_TIMEOUT
            ),
            read_bufsize=8192,
        ) as session:
            for test_url in SINGBOX_TEST_URLS:
                remaining = deadline - time.monotonic()
                if remaining <= 0.3:
                    break

                request_timeout = min(SINGBOX_REQUEST_TIMEOUT, remaining)
                request_start = time.monotonic()
                try:
                    async with session.get(
                        test_url,
                        proxy=f"http://127.0.0.1:{port}",
                        timeout=aiohttp.ClientTimeout(
                            total=request_timeout, connect=request_timeout
                        ),
                        ssl=False,
                        allow_redirects=False,
                    ) as resp:
                        if 200 <= resp.status < 400:
                            speed = round((time.monotonic() - request_start) * 1000, 1)
                            return proxy_link, proxy_type, True, speed
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue

        return proxy_link, proxy_type, False, 0.0

    except asyncio.CancelledError:
        raise
    except Exception:
        return proxy_link, proxy_type, False, 0.0
    finally:
        if proc is not None:
            await _stop_process(proc)
        try:
            os.unlink(config_path)
        except OSError:
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

        http_request = (
            b"GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n"
        )

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


async def check_mtproto_telethon(
    server: str, port: int, secret: str, timeout: int
) -> Tuple[bool, float]:
    try:
        from telethon import TelegramClient
        from telethon.errors import AuthKeyError, FloodWaitError, RPCError

        proxy = (server, port, secret)

        client = TelegramClient(
            "anon",
            api_id=12345,
            api_hash="a1b2c3d4e5f6g7h8i9j0",
            proxy=proxy,
            connection_retries=1,
            timeout=timeout,
        )

        try:
            await client.connect()

            if await client.is_ready():
                await client.disconnect()
                return True, 1

            await client.disconnect()
            return False, 0
        except (AuthKeyError, RPCError, FloodWaitError):
            try:
                await client.disconnect()
            except Exception:
                pass
            return False, 0
        except Exception:
            try:
                await client.disconnect()
            except Exception:
                pass
            return False, 0
    except ImportError:
        return False, 0
    except Exception:
        return False, 0


async def check_mtproto_all_methods(
    server: str, port: int, secret: str, timeout: int
) -> Tuple[bool, float]:
    start = time.time()

    methods = [
        asyncio.create_task(check_mtproto_tcp(server, port, timeout)),
        asyncio.create_task(check_mtproto_handshake(server, port, secret, timeout)),
        asyncio.create_task(check_mtproto_http(server, port, secret, timeout)),
    ]
    done, pending = await asyncio.wait(methods, return_when=asyncio.FIRST_COMPLETED)

    ok = any(res.result()[0] for res in done)
    for task in pending:
        task.cancel()

    if not ok:
        for task in asyncio.as_completed(
            [asyncio.create_task(check_mtproto_telethon(server, port, secret, timeout))]
        ):
            ok = (await task)[0]

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


def _check_tor_dependencies(bridge_type: str) -> str | None:
    if not TOR_INSTALLED:
        return f"tor not found at {TOR_PATH} - run ./setup.sh"
    if bridge_type in ("TOR_OBFS4", "TOR_WEBTUNNEL") and not LYREBIRD_INSTALLED:
        return f"lyrebird not found at {LYREBIRD_PATH} - run ./setup.sh"
    if bridge_type == "TOR_SNOWFLAKE" and not SNOWFLAKE_CLIENT_INSTALLED:
        return (
            f"snowflake-client not found at {SNOWFLAKE_CLIENT_PATH} - "
            "install it (package snowflake-client or build from "
            "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake)"
        )
    return None


async def check_tor_bridge(
    bridge_line: str, bridge_type: str, timeout: int = 90
) -> Tuple[bool, float]:
    if timeout < TOR_BOOTSTRAP_TIMEOUT:
        timeout = TOR_BOOTSTRAP_TIMEOUT

    dep_error = _check_tor_dependencies(bridge_type)
    if dep_error:
        raise RuntimeError(dep_error)

    bridge_data = parse_bridge_line(bridge_line)
    if not bridge_data:
        return False, 0.0

    bridge_type_lower = bridge_type.replace("TOR_", "").lower()
    if bridge_data["protocol"] != bridge_type_lower:
        return False, 0.0

    if bridge_type in ("TOR_OBFS4", "TOR_WEBTUNNEL"):
        host = bridge_data["host"].strip("[]")
        try:
            pre_ok, _ = await tcp_precheck(host, int(bridge_data["port"]))
        except Exception:
            pre_ok = False
        if not pre_ok:
            return False, 0.0

    socks_port = get_free_port(start=TOR_CHECK_PORTS_START)
    control_port = get_free_port(start=TOR_CHECK_PORTS_START)
    guard = 0
    while control_port == socks_port and guard < 10:
        control_port = get_free_port(start=TOR_CHECK_PORTS_START)
        guard += 1
    if control_port == socks_port:
        return False, 0.0

    if bridge_type == "TOR_SNOWFLAKE":
        transport_lines = [
            f"ClientTransportPlugin snowflake exec {SNOWFLAKE_CLIENT_PATH}"
        ]
    else:
        transport_lines = [
            f"ClientTransportPlugin obfs4 exec {LYREBIRD_PATH}",
            f"ClientTransportPlugin webtunnel exec {LYREBIRD_PATH}",
        ]

    bridge_line_clean = " ".join(strip_bridge_prefix(bridge_line).split())

    torrc_lines = [
        f"SocksPort 127.0.0.1:{socks_port}",
        f"ControlPort 127.0.0.1:{control_port}",
        "CookieAuthentication 1",
        "UseBridges 1",
        *transport_lines,
        f"Bridge {bridge_line_clean}",
        "SafeLogging 0",
        "Log notice file tor.log",
        "DataDirectory .",
    ]
    torrc = "\n".join(torrc_lines)

    workdir = tempfile.mkdtemp(prefix="torbridge_")
    torrc_path = os.path.join(workdir, "torrc")
    with open(torrc_path, "w") as f:
        f.write(torrc + "\n")

    proc = None
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            TOR_PATH,
            "-f",
            torrc_path,
            cwd=workdir,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        log_path = os.path.join(workdir, "tor.log")
        deadline = start + timeout
        log_offset = 0

        while time.time() < deadline:
            if proc.returncode is not None:
                break

            try:
                with open(log_path, "r", errors="replace") as lf:
                    lf.seek(log_offset)
                    chunk = lf.read()
                    log_offset = lf.tell()
                if chunk:
                    for line in chunk.splitlines():
                        if "Bootstrapped 100" in line:
                            return True, round((time.time() - start) * 1000, 1)
            except FileNotFoundError:
                pass
            except OSError:
                pass

            await asyncio.sleep(0.5)

        return False, 0.0
    except Exception:
        return False, 0.0
    finally:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(workdir, ignore_errors=True)
