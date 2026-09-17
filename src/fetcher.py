import asyncio
from typing import List

import aiohttp

from utils import PROXY_PREFIXES


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
                        elif line.lower().startswith(PROXY_PREFIXES):
                            proxies.append(line)
                        elif ":" in line:
                            if line.count(":") == 1:
                                proxies.append(line)
                    return proxies
    except Exception:
        pass
    return []
