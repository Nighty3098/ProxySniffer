import base64
import binascii
from typing import Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse


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


def parse_mtproto_link(link: str) -> Optional[Dict]:
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


def parse_hysteria2_link(link: str) -> Optional[Dict]:
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


def parse_shadowsocks_link(link: str) -> Optional[Dict]:
    try:
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


def parse_trojan_link(link: str) -> Optional[Dict]:
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

            password = unquote(password)

            result = {"server": host, "port": port, "password": password}

            if params:
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
                result["insecure"] = qs.get("insecure", qs.get("allowInsecure", ["0"]))[0]

                if qs.get("grpc", [""])[0]:
                    result["type"] = "grpc"
                    result["serviceName"] = qs.get("serviceName", [""])[0]

            return result
    except Exception:
        pass
    return None


def parse_vmess_link(link: str) -> Optional[Dict]:
    try:
        if not link.startswith("vmess://"):
            return None
        link = link.replace("vmess://", "")

        try:
            padding = 4 - len(link) % 4
            if padding != 4 and padding > 0:
                link += "=" * padding
            decoded = base64.b64decode(link, validate=True).decode()
            import json

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


def parse_vless_link(link: str) -> Optional[Dict]:
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
