import asyncio
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime
from multiprocessing import cpu_count
from typing import List, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp

from colorama import Fore, init
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

console = Console()

init(autoreset=True)

CPU_CORES = cpu_count()
DEFAULT_WORKERS = max(8, CPU_CORES * 2)

from links import (
    proxy_HTTP,
    proxy_HTTPS,
    proxy_HYSTERIA2,
    proxy_MTPROTO,
    proxy_SHADOW_SOCKS,
    proxy_SOCKS4,
    proxy_SOCKS5,
    proxy_TROJAN,
    proxy_VMESS,
    proxy_VLESS,
)

proxy_sources = {
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

SINGBOX_PATH = "/tmp/sing-box-1.13.4-linux-amd64/sing-box"
SINGBOX_INSTALLED = os.path.exists(SINGBOX_PATH)
TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.apple.com/library/test/success.html",
]

SINGBOX_POOL_SIZE = max(4, CPU_CORES)


def get_free_port(start: int = 15000, end: int = 60000) -> int:
    import random
    import socket
    while True:
        port = random.randint(start, end)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", port))
            sock.close()
            return port
        except OSError:
            continue


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
                "alterId": vm_data.get("aid", 0),
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
                hy_outbound["tls"]["utls"] = {"enabled": True, "fingerprint": hy_data["fp"]}

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
    import socket
    import aiohttp

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
            SINGBOX_PATH, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        for _ in range(timeout * 2):
            await asyncio.sleep(0.5)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port),
                    timeout=1
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
                                ssl=False
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
            timeout=timeout + 5
        )
        return result[2], result[3]
    except asyncio.TimeoutError:
        return False, 0.0
    except Exception:
        return False, 0.0


async def check_with_singbox_batch(
    proxies: List[Tuple[str, str]],
    timeout: int = 10,
    max_workers: int = SINGBOX_POOL_SIZE,
) -> List[Tuple[str, str, bool, float]]:
    if not proxies:
        return []

    semaphore = asyncio.Semaphore(max_workers)

    async def check_one(proxy_tuple):
        async with semaphore:
            link, ptype = proxy_tuple
            port = get_free_port()
            try:
                result = await asyncio.wait_for(
                    _check_singbox_async(link, ptype, port, timeout),
                    timeout=timeout + 5
                )
                return result
            except:
                return (link, ptype, False, 0.0)

    tasks = [check_one(p) for p in proxies]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_results = []
    for r in results:
        if isinstance(r, tuple) and len(r) == 4:
            valid_results.append(r)

    return valid_results


async def check_all_parallel(
    proxies_list: List[str], proxy_type: str, batch_size: int = DEFAULT_WORKERS
) -> List[Tuple[str, float]]:
    if not proxies_list:
        return []
    loop = asyncio.get_event_loop()

    if proxy_type.upper() in ["HTTP", "HTTPS", "SOCKS4", "SOCKS5"]:
        return await check_proxies_async(proxies_list, proxy_type, show_progress=True)

    singbox_types = ["VMESS", "VLESS", "TROJAN", "HYSTERIA2", "SHADOW_SOCKS"]
    if proxy_type.upper() in singbox_types:
        proxy_tuples = [(p, proxy_type) for p in proxies_list]

        results = []
        working_count = 0
        failed_count = 0
        start_time = time.time()

        max_concurrent = min(batch_size, 8)
        semaphore = asyncio.Semaphore(max_concurrent)
        lock = asyncio.Lock()

        progress_columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[cyan]{task.fields[status]}[/cyan]"),
        ]

        async def check_one(proxy_tuple):
            nonlocal working_count, failed_count
            async with semaphore:
                link, ptype = proxy_tuple
                
                if ptype.upper() == "VLESS":
                    vl_data = parse_vless_link(link)
                    if vl_data:
                        ok, speed = await check_vless(vl_data, timeout=6)
                        if ok:
                            async with lock:
                                working_count += 1
                                results.append((link, speed))
                                checked = working_count + failed_count
                                elapsed = time.time() - start_time
                                if checked > 0:
                                    eta_sec = int((elapsed / checked) * (len(proxies_list) - checked))
                                else:
                                    eta_sec = 0
                                progress.update(
                                    task,
                                    advance=1,
                                    status=f"[cyan]{checked}[/cyan]/[yellow]{len(proxies_list)}[/yellow] | [green]✓{working_count}[/green] | [red]✗{failed_count}[/red]",
                                )
                            return
                
                ok, speed = await check_with_singbox(link, ptype, timeout=8)

                async with lock:
                    if ok and speed > 0:
                        working_count += 1
                        results.append((link, speed))
                    else:
                        failed_count += 1

                    checked = working_count + failed_count
                    elapsed = time.time() - start_time
                    if checked > 0:
                        eta_sec = int(
                            (elapsed / checked) * (len(proxies_list) - checked)
                        )
                        eta_str = f"ETA: {eta_sec // 60}m"
                    else:
                        eta_str = ""

                    progress.update(
                        task,
                        advance=1,
                        status=f"[cyan]{checked}[/cyan]/[yellow]{len(proxies_list)}[/yellow] | [green]✓{working_count}[/green] | [red]✗{failed_count}[/red]",
                    )

        with Progress(*progress_columns, console=console) as progress:
            task = progress.add_task(
                f"[green]Checking {proxy_type}...",
                total=len(proxies_list),
                status=f"[yellow]0/{len(proxies_list)}[/yellow] | [red]✗ 0[/red]",
            )

            tasks = [asyncio.create_task(check_one(p)) for p in proxy_tuples]

            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except asyncio.CancelledError:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        results.sort(key=lambda x: x[1])
        return results

    return await check_proxies_async(proxies_list, proxy_type, show_progress=True)


def parse_proxy(proxy: str) -> str:
    proxy = proxy.strip()

    for prefix in (
        "http://",
        "https://",
        "socks4://",
        "socks5://",
        "socks4h://",
        "socks5h://",
    ):
        if proxy.lower().startswith(prefix):
            return proxy[len(prefix) :].strip()

    return proxy


def parse_mtproto_link(link: str) -> dict | None:
    try:
        if not link.startswith("https://t.me/proxy"):
            return None
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        server = params.get("server", [""])[0]
        port = params.get("port", [""])[0]
        secret = params.get("secret", [""])[0]
        if server and port and secret:
            return {"server": server, "port": port, "secret": secret}
    except:
        pass
    return None


def parse_hysteria2_link(link: str) -> dict | None:
    try:
        if not link.startswith("hysteria2://"):
            return None
        link = link.replace("hysteria2://", "")
        if "#" in link:
            link = link.split("#")[0]

        password = ""
        host_port = ""

        if "@" in link:
            parts = link.split("@", 1)
            password = parts[0]
            host_port = parts[1]
        else:
            return None

        result = {"server": "", "port": 0, "password": password}

        if "?" in host_port:
            host_port, params_str = host_port.split("?", 1)
            params_str = params_str.replace(";", "&")
            params = parse_qs(params_str)
            result["insecure"] = params.get("insecure", [""])[0]
            result["sni"] = params.get("sni", [""])[0]
            result["fp"] = params.get("fp", [""])[0]
            result["mport"] = params.get("mport", [""])[0]

        if ":" in host_port:
            host, port = host_port.split(":")
            port = int(port.split("?")[0])
            result["server"] = host
            result["port"] = port
            return result
    except Exception:
        pass
    return None


def parse_shadowsocks_link(link: str) -> dict | None:
    try:
        import base64
        import binascii

        if not link.startswith("ss://"):
            return None
        link = link.replace("ss://", "")
        if "#" in link:
            link = link.split("#")[0]

        plugin = None
        if "?plugin=" in link or "&plugin=" in link:
            if "?plugin=" in link:
                plugin_part = link.split("?plugin=", 1)[1]
            else:
                plugin_part = link.split("&plugin=", 1)[1]
            if "&" in plugin_part:
                plugin = plugin_part.split("&", 1)[0]
            else:
                plugin = plugin_part
            link = link.split("?plugin=")[0].split("&plugin=")[0]

        userinfo = ""
        host_port = ""

        if "@" in link:
            parts = link.split("@", 1)
            userinfo = parts[0]
            host_port = parts[1]
        else:
            padding = 4 - len(link) % 4
            if padding != 4 and padding > 0:
                link += "=" * padding
            try:
                decoded = base64.b64decode(link, validate=True).decode()
            except:
                return None

            if "@" in decoded:
                parts = decoded.split("@", 1)
                userinfo = parts[0]
                host_port = parts[1]
            else:
                return None

        if ":" in host_port:
            parts = host_port.rsplit(":", 1)
            host = parts[0]
            port = parts[1].split("?")[0]

            method = "aes-256-gcm"
            password = ""

            try:
                padding = 4 - len(userinfo) % 4
                if padding != 4 and padding > 0:
                    userinfo += "=" * padding
                decoded = base64.b64decode(userinfo, validate=True).decode()
            except (binascii.Error, Exception):
                decoded = userinfo

            if ":" in decoded:
                method_password = decoded.split(":", 1)
                method = method_password[0] if method_password[0] else "aes-256-gcm"
                password = method_password[1] if len(method_password) > 1 else ""

            return {
                "server": host,
                "port": int(port),
                "method": method,
                "password": password,
                "plugin": plugin,
            }
    except Exception:
        pass
    return None


def parse_trojan_link(link: str) -> dict | None:
    try:
        if not link.startswith("trojan://"):
            return None
        link = link.replace("trojan://", "")
        if "#" in link:
            link = link.split("#")[0]
        if "@" in link:
            parts = link.split("?")
            password_host = parts[0]
            params = parts[1] if len(parts) > 1 else ""

            password, host_port = password_host.rsplit("@", 1)
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 443

            from urllib.parse import unquote

            password = unquote(password)

            result = {"server": host, "port": port, "password": password}

            if params:
                from urllib.parse import unquote

                params = unquote(params)
                params = params.replace(";", "&")
                qs = parse_qs(params)
                result["security"] = qs.get("security", [""])[0]
                result["sni"] = qs.get("sni", [""])[0] or qs.get("peer", [""])[0]
                result["fp"] = qs.get("fp", [""])[0]

                ws_val = qs.get("ws", [""])[0].lower()
                if ws_val == "1" or ws_val == "true":
                    result["type"] = "ws"
                else:
                    result["type"] = qs.get("type", qs.get("network", ["tcp"]))[0]

                result["path"] = qs.get("path", qs.get("wspath", [""]))[0]
                result["host"] = qs.get("host", [""])[0]
                result["alpn"] = qs.get("alpn", [""])[0]
                result["insecure"] = qs.get("insecure", qs.get("allowInsecure", ["0"]))[
                    0
                ]

                if qs.get("grpc", [""])[0]:
                    result["type"] = "grpc"
                    result["serviceName"] = qs.get("serviceName", [""])[0]

            return result
    except Exception:
        pass
    return None


def parse_vmess_link(link: str) -> dict | None:
    try:
        if not link.startswith("vmess://"):
            return None
        link = link.replace("vmess://", "")
        import base64
        import json

        try:
            padding = 4 - len(link) % 4
            if padding != 4 and padding > 0:
                link += "=" * padding
            decoded = base64.b64decode(link, validate=True).decode()
            data = json.loads(decoded)

            if not data.get("add") or not data.get("port") or not data.get("id"):
                return None

            try:
                aid = int(data.get("aid", 0))
            except (ValueError, TypeError):
                aid = 0

            return {
                "server": data.get("add", ""),
                "port": int(data.get("port", 0)),
                "id": data.get("id", ""),
                "aid": aid,
                "net": data.get("net", "tcp"),
                "tls": data.get("tls", ""),
                "sni": data.get("sni", ""),
                "host": data.get("host", ""),
                "path": data.get("path", ""),
                "fp": data.get("fp", ""),
                "insecure": data.get("insecure", "0"),
                "allowInsecure": data.get("allowInsecure", "0"),
            }
        except Exception:
            pass
    except Exception:
        pass
    return None


def parse_vless_link(link: str) -> dict | None:
    try:
        if not link.startswith("vless://"):
            return None
        link = link.replace("vless://", "")
        if "#" in link:
            link = link.split("#")[0]
        if "@" in link:
            parts = link.split("?")
            id_host = parts[0]
            params = parts[1] if len(parts) > 1 else ""

            id_, host_port = id_host.split("@")
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 443

            result = {"server": host, "port": port, "id": id_}

            if params:
                params = unquote(params)
                qs = parse_qs(params)
                result["security"] = qs.get("security", ["none"])[0]
                result["sni"] = qs.get("sni", [""])[0]
                result["fp"] = qs.get("fp", [""])[0]
                result["type"] = qs.get("type", ["tcp"])[0]
                result["path"] = qs.get("path", [""])[0]
                result["flow"] = qs.get("flow", [""])[0]
                result["pbk"] = qs.get("pbk", [""])[0]
                result["sid"] = qs.get("sid", [""])[0]
                result["host"] = qs.get("host", [""])[0]
                result["serviceName"] = qs.get("serviceName", [""])[0]
                result["mode"] = qs.get("mode", [""])[0]
                result["insecure"] = qs.get("insecure", ["0"])[0]
                result["allowInsecure"] = qs.get("allowInsecure", ["0"])[0]

            return result
    except:
        pass
    return None


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


async def check_vmess(vm_data: dict, timeout: int) -> Tuple[bool, float]:
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


async def check_vless(vl_data: dict, timeout: int) -> Tuple[bool, float]:
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


async def check_hysteria2_full(hy_data: dict, timeout: int) -> Tuple[bool, float]:
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


async def check_proxy(
    session,
    proxy: str,
    proxy_type: str,
    test_url: str = "https://httpbin.org/ip",
    timeout: int = 10,
) -> Tuple[bool, float]:
    try:
        start = time.time()

        if proxy_type.upper() == "MTPROTO":
            mt_data = parse_mtproto_link(proxy)
            if not mt_data:
                return False, 0.0

            ok, _ = await check_mtproto_all_methods(
                mt_data["server"], int(mt_data["port"]), mt_data["secret"], timeout
            )

            if ok:
                speed = round((time.time() - start) * 1000, 1)
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "HYSTERIA2":
            ok, speed = await check_with_singbox(proxy, proxy_type, timeout)
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "SHADOW_SOCKS":
            ok, speed = await check_with_singbox(proxy, proxy_type, timeout)
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "TROJAN":
            tr_data = parse_trojan_link(proxy)
            if not tr_data:
                return False, 0.0

            security = tr_data.get("security", "")
            net_type = tr_data.get("type", "tcp")

            ok, speed = await check_with_singbox(proxy, proxy_type, timeout)
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "VMESS":
            ok, speed = await check_with_singbox(proxy, proxy_type, timeout)
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "VLESS":
            vl_data = parse_vless_link(proxy)
            if vl_data:
                ok, speed = await check_vless(vl_data, timeout=timeout)
                if ok:
                    return True, speed
            
            ok, speed = await check_with_singbox(proxy, proxy_type, timeout)
            if ok:
                return True, speed
            return False, 0.0

        clean_proxy = parse_proxy(proxy)

        if proxy_type.upper() in ["HTTP", "HTTPS"]:
            scheme = "http" if proxy_type.upper() == "HTTP" else "https"
            proxy_url = f"{scheme}://{clean_proxy}"
        elif proxy_type.upper() == "SOCKS4":
            proxy_url = f"socks4://{clean_proxy}"
        elif proxy_type.upper() == "SOCKS5":
            proxy_url = f"socks5://{clean_proxy}"
        else:
            return False, 0.0

        async with session.get(
            test_url, proxy=proxy_url, timeout=timeout, ssl=False
        ) as response:
            if response.status == 200:
                speed = round((time.time() - start) * 1000, 1)
                return True, speed
    except:
        pass
    return False, 0.0


async def check_proxies_async(
    proxies_list: List[str],
    proxy_type: str,
    max_concurrent: int = DEFAULT_WORKERS * 10,
    show_progress: bool = True,
):
    connector = aiohttp.TCPConnector(
        limit=max_concurrent * 2,
        ssl=False,
        limit_per_host=max_concurrent,
        ttl_dns_cache=600,
        keepalive_timeout=30,
        enable_cleanup_closed=True,
    )

    test_url = "https://httpbin.org/ip"
    working_list = []
    failed = 0
    checked = 0
    lock = asyncio.Lock()

    progress_columns = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[cyan]{task.fields[status]}[/cyan]"),
    ]

    with Progress(*progress_columns, console=console) as progress:
        task = progress.add_task(
            f"[green]Checking {proxy_type}...",
            total=len(proxies_list),
            status=f"[yellow]0/{len(proxies_list)}[/yellow] | [red]✗ 0[/red]",
        )

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=8, connect=2),
            read_bufsize=65536,
        ) as session:
            semaphore = asyncio.Semaphore(max_concurrent)

            async def bounded_check(p):
                nonlocal checked, failed
                async with semaphore:
                    try:
                        ok, speed = await check_proxy(
                            session, p, proxy_type, test_url=test_url, timeout=4
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        ok, speed = False, 0.0

                    checked += 1
                    if not ok:
                        failed += 1

                    working = checked - failed
                    try:
                        progress.update(
                            task,
                            advance=1,
                            status=f"[cyan]{checked}[/cyan]/[yellow]{len(proxies_list)}[/yellow] | [green]✓{working}[/green] | [red]✗{failed}[/red]",
                        )
                    except Exception:
                        pass

                    if show_progress:
                        if ok and speed > 0:
                            console.print(
                                f"[green]✓[/green] [cyan]{p[:50]}[/cyan] [magenta]{speed}ms[/magenta]"
                            )
                        else:
                            console.print(f"[red]✗[/red] [dim]{p[:50]}[/dim]")

                    if ok and speed > 0:
                        async with lock:
                            working_list.append((p, speed))

                    return p, ok, speed

            tasks = [asyncio.create_task(bounded_check(p)) for p in proxies_list]

            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except asyncio.CancelledError:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                # Collect results from completed tasks (they already added to 'working_list' list)

    working_list.sort(key=lambda x: x[1])
    return working_list


async def fetch_proxies(url: str) -> List[str]:
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    proxies = []
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if "t.me/proxy" in line.lower():
                            proxies.append(line)
                        elif any(
                            line.lower().startswith(p)
                            for p in (
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
                            )
                        ):
                            proxies.append(line)
                        elif ":" in line:
                            if line.count(":") == 1:
                                proxies.append(line)
                    return proxies
    except Exception:
        pass
    return []


async def load_proxies_from_sources(proxy_type: str) -> List[str]:
    sources = proxy_sources.get(proxy_type.upper(), [])
    all_proxies: set = set()

    console.print(
        f"[cyan][*] Downloading {proxy_type} proxies from {len(sources)} sources...[/cyan]"
    )

    tasks = [fetch_proxies(url) for url in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            all_proxies.update(result)

    unique_proxies = list(all_proxies)
    console.print(
        f"[green][+] Loaded {len(unique_proxies)} unique {proxy_type} proxies[/green]"
    )
    return unique_proxies


def save_working_proxies(working: List[Tuple], proxy_type: str):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{proxy_type.lower()}_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        for proxy, speed in working:
            f.write(f"{proxy}  # {speed}ms\n")

    console.print(
        f"[green][+] Saved {len(working)} working proxies to {filename}[/green]"
    )


def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    console.print("")
    console.print("[red]  ▄▄▄·▄▄▄        ▐▄• ▄  ▄· ▄▌.▄▄ ·  ▐ ▄ ▪  ·▄▄▄·▄▄▄▄▄▄ .▄▄▄  ")
    console.print("[red] ▐█ ▄█▀▄ █·▪      █▌█▌▪▐█▪██▌▐█ ▀. •█▌▐███ ▐▄▄·▐▄▄·▀▄.▀·▀▄ █·")
    console.print("[red]  ██▀·▐▀▀▄  ▄█▀▄  ·██· ▐█▌▐█▪▄▀▀▀█▄▐█▐▐▌▐█·██▪ ██▪ ▐▀▀▪▄▐▀▀▄ ")
    console.print("[red] ▐█▪·•▐█•█▌▐█▌.▐▌▪▐█·█▌ ▐█▀·.▐█▄▪▐███▐█▌▐█▌██▌.██▌.▐█▄▄▌▐█•█▌")
    console.print("[red] .▀   .▀  ▀ ▀█▄▀▪•▀▀ ▀▀  ▀ •  ▀▀▀▀ ▀▀ █▪▀▀▀▀▀▀ ▀▀▀  ▀▀▀ .▀  ▀")
    console.print("")
    console.print("[red]=" * 65)
    console.print("[red]           PROXY CHECKER TOOL - By Nighty3098")
    console.print("[red]=" * 65)
    console.print(
        f"[cyan][*] CPU Cores: {CPU_CORES} | Workers: {DEFAULT_WORKERS}[/cyan]"
    )


def main_menu():
    console.print("")
    console.print("[1] HTTP Proxy")
    console.print("[2] HTTPS Proxy")
    console.print("[3] SOCKS4 Proxy")
    console.print("[4] SOCKS5 Proxy")
    console.print("[5] MTPROTO Proxy")
    console.print("[6] HYSTERIA2 Proxy")
    console.print("[7] SHADOW_SOCKS Proxy")
    console.print("[8] TROJAN Proxy")
    console.print("[9] VMESS Proxy")
    console.print("[10] VLESS Proxy")
    console.print("[0] Exit")


async def main():
    while True:
        print_banner()
        main_menu()

        try:
            choice = int(console.input("\n[yellow][SELECT OPTION] > [/yellow]"))
        except ValueError:
            continue

        if choice == 0:
            console.print("\n[red][!] Exiting...[/red]")
            break
        elif choice not in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
            console.print("\n[red][!] Invalid option![/red]")
            time.sleep(1)
            continue

        proxy_type = proxy_mapping[choice]

        default_limit = (
            500
            if proxy_type
            in ["VMESS", "VLESS", "TROJAN", "HYSTERIA2", "SHADOW_SOCKS", "MTPROTO"]
            else 2000
        )

        try:
            print_banner()
            list_limit_input = console.input(
                f"\n[yellow][PROXY LIMIT] (default: {default_limit}) > [/yellow]"
            )
            list_limit = (
                int(list_limit_input) if list_limit_input.strip() else default_limit
            )
        except ValueError:
            list_limit = default_limit

        print_banner()
        console.print(f"[cyan][*] Loading {proxy_type} proxies...[/cyan]")
        proxies = await load_proxies_from_sources(proxy_type)

        if proxy_type in ["VLESS", "VMESS", "TROJAN", "HYSTERIA2", "SHADOW_SOCKS"] and not SINGBOX_INSTALLED:
            console.print(f"[red][!] WARNING: sing-box not found at {SINGBOX_PATH}[/red]")
            console.print(f"[red][!] Using fallback socket check (less accurate)[/red]")
            time.sleep(2)

        if not proxies:
            console.print(f"[red][!] No proxies loaded from sources![/red]")
            time.sleep(2)
            continue

        proxies = proxies[:list_limit]
        console.print(f"[green][+] Loaded {len(proxies)} proxies[/green]")

        console.print(f"[green][*] Checking {proxy_type} proxies...[/green]")
        console.print(
            f"[cyan][*] Using {DEFAULT_WORKERS} workers for parallel checking[/cyan]"
        )
        console.print(f"[yellow][*] Press Ctrl+C to stop and see results[/yellow]")

        working = []
        stopped = False

        try:
            working = await check_all_parallel(proxies, proxy_type)
        except (KeyboardInterrupt, asyncio.CancelledError):
            stopped = True
            console.print(f"\n[yellow][!] Stopped by user[/yellow]")
        except Exception as e:
            console.print(f"\n[red][!] Error: {e}[/red]")

        if not working and not stopped:
            console.print(f"\n[green][+] Found {len(working)} working proxies[/green]")
        elif stopped:
            console.print(f"\n[cyan]Found {len(working)} working proxies before stop[/cyan]")

        if not working:
            console.print(f"[yellow][*] No working proxies found[/yellow]")
            time.sleep(2)
            continue

        console.print(f"\n[cyan][1] Save to file")
        console.print("[2] Show in console")
        console.print("[3] Back to main menu")

        try:
            output_choice = int(console.input("\n[yellow][OUTPUT OPTION] > [/yellow]"))
        except ValueError:
            output_choice = 3

        if output_choice == 1:
            save_working_proxies(working, proxy_type)
            time.sleep(2)
        elif output_choice == 2:
            console.print(f"\n[cyan]{'=' * 40}[/cyan]")
            console.print(
                f"[bold cyan]WORKING PROXIES (IP:PORT | RESPONSE TIME)[/bold cyan]"
            )
            console.print(f"[cyan]{'=' * 40}[/cyan]")

            result_table = Table(show_header=True, header_style="bold magenta")
            result_table.add_column("Proxy", style="cyan")
            result_table.add_column("Speed", style="green")

            for proxy, response_time in working:
                result_table.add_row(proxy, f"{response_time}ms")

            console.print(result_table)
            input(Fore.YELLOW + "\nPress Enter to continue..." + Fore.RESET)


if __name__ == "__main__":
    asyncio.run(main())
