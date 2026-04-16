import asyncio
from typing import List

import aiohttp


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
