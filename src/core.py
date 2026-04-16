import asyncio
import time
from typing import List, Tuple

import aiohttp
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from checker import (
    check_mtproto_all_methods,
    check_vless,
    check_with_singbox,
    generate_singbox_config,
)
from config import DEFAULT_WORKERS
from fetcher import fetch_proxies
from parsers import (
    parse_mtproto_link,
    parse_proxy,
    parse_trojan_link,
    parse_vless_link,
)

console = Console()


async def load_proxies_from_sources(proxy_sources: dict, proxy_type: str) -> List[str]:
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

    working_list.sort(key=lambda x: x[1])
    return working_list


async def check_with_singbox_batch(
    proxies: List[Tuple[str, str]],
    timeout: int = 10,
    max_workers: int = 8,
) -> List[Tuple[str, str, bool, float]]:
    if not proxies:
        return []

    from config import SINGBOX_POOL_SIZE
    from utils import get_free_port
    from checker import _check_singbox_async

    max_workers = max_workers or SINGBOX_POOL_SIZE
    semaphore = asyncio.Semaphore(max_workers)

    async def check_one(proxy_tuple):
        async with semaphore:
            link, ptype = proxy_tuple
            port = get_free_port()
            try:
                result = await asyncio.wait_for(
                    _check_singbox_async(link, ptype, port, timeout),
                    timeout=timeout + 5,
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
    proxies_list: List[str],
    proxy_type: str,
    batch_size: int = DEFAULT_WORKERS,
) -> List[Tuple[str, float]]:
    if not proxies_list:
        return []

    if proxy_type.upper() in ["HTTP", "HTTPS", "SOCKS4", "SOCKS5"]:
        return await check_proxies_async(proxies_list, proxy_type, show_progress=True)

    from config import SINGBOX_POOL_SIZE
    from parsers import parse_vless_link

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
                    else:
                        ok, speed = False, 0.0
                else:
                    ok, speed = await check_with_singbox(link, ptype, timeout=8)

                async with lock:
                    if ok and speed > 0:
                        working_count += 1
                        results.append((link, speed))

                        console.print(
                            f"[green]✓[/green] [cyan]{link[:60]}...[/cyan] [magenta]{speed}ms[/magenta]"
                        )

                    else:
                        failed_count += 1
                        console.print(
                            f"[red]x[/red] [cyan]{link[:60]}...[/cyan] [magenta]{speed}ms[/magenta]"
                        )

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
                try:
                    await asyncio.gather(*tasks, return_exceptions=True)
                except:
                    pass

        try:
            results.sort(key=lambda x: x[1])
        except:
            pass
        return results

    return await check_proxies_async(proxies_list, proxy_type, show_progress=True)
