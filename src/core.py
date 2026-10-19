import asyncio
import concurrent.futures
import functools
import threading
import time
from typing import Callable, List, Tuple

import aiohttp
from rich.console import Console

from checker import (
    TCP_PRECHECK_TYPES,
    _check_singbox_async,
    _check_tor_dependencies,
    check_mtproto_all_methods,
    check_tor_bridge,
    check_with_singbox,
    get_link_server,
    tcp_precheck,
)
from config import (
    CHECK_THREADS,
    HTTP_CHECK_CONNECT_TIMEOUT,
    HTTP_CHECK_REQUEST_TIMEOUT,
    HTTP_CHECK_SESSION_TIMEOUT,
    HTTP_MAX_CONCURRENT,
    SINGBOX_CHECK_TIMEOUT,
    SINGBOX_INSTALLED,
    SINGBOX_MAX_CONCURRENT,
    SINGBOX_PATH,
    SINGBOX_PRECHECK_CONCURRENT,
    TEST_URLS,
    TOR_BOOTSTRAP_TIMEOUT,
    TOR_MAX_CONCURRENT,
)

TOR_TYPES = ("TOR_OBFS4", "TOR_WEBTUNNEL", "TOR_SNOWFLAKE")
SINGBOX_TYPES = ("VMESS", "VLESS", "TROJAN", "HYSTERIA2", "SHADOW_SOCKS")

from fetcher import fetch_proxies
from parsers import filter_and_dedupe, parse_mtproto_link, parse_proxy
from utils import get_free_port

console = Console()


async def load_proxies_from_sources(
    proxy_sources: dict, proxy_type: str, quiet: bool = False
) -> List[str]:
    sources = proxy_sources.get(proxy_type.upper(), [])

    if not quiet:
        console.print(
            f"[cyan][*] Downloading {proxy_type} proxies from {len(sources)} sources...[/cyan]"
        )

    tasks = [fetch_proxies(url) for url in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_lines: List[str] = []
    for result in results:
        if isinstance(result, list):
            all_lines.extend(result)

    # Sources are frequently mixed: keep only entries of the requested
    # protocol and deduplicate by config identity before any checks start.
    unique_proxies, filtered_out, duplicates = filter_and_dedupe(
        all_lines, proxy_type
    )

    if not quiet:
        console.print(
            f"[green][+] Loaded {len(unique_proxies)} unique {proxy_type} proxies[/green]"
        )
        if filtered_out or duplicates:
            console.print(
                f"[yellow][-] Filtered out {filtered_out} links of other protocols, "
                f"removed {duplicates} duplicates[/yellow]"
            )
    return unique_proxies


async def check_proxy(
    session,
    proxy: str,
    proxy_type: str,
    test_url: str = None,
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

        if proxy_type.upper() in ("TOR_OBFS4", "TOR_WEBTUNNEL", "TOR_SNOWFLAKE"):
            try:
                ok, speed = await check_tor_bridge(
                    proxy, proxy_type.upper(), max(timeout, TOR_BOOTSTRAP_TIMEOUT)
                )
            except RuntimeError as dep_err:
                console.print(f"[red][!] {dep_err}[/red]")
                return False, 0.0
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "HYSTERIA2":
            ok, speed = await check_with_singbox(
                proxy, proxy_type, timeout=SINGBOX_CHECK_TIMEOUT
            )
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "SHADOW_SOCKS":
            ok, speed = await check_with_singbox(
                proxy, proxy_type, timeout=SINGBOX_CHECK_TIMEOUT
            )
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "TROJAN":
            ok, speed = await check_with_singbox(
                proxy, proxy_type, timeout=SINGBOX_CHECK_TIMEOUT
            )
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "VMESS":
            ok, speed = await check_with_singbox(
                proxy, proxy_type, timeout=SINGBOX_CHECK_TIMEOUT
            )
            if ok:
                return True, speed
            return False, 0.0

        if proxy_type.upper() == "VLESS":
            # VLESS can only be validated by actually passing traffic
            # through the tunnel. TCP/TLS reachability of the endpoint
            # says nothing about UUID/REALITY/SNI correctness.
            ok, speed = await check_with_singbox(
                proxy, proxy_type, timeout=SINGBOX_CHECK_TIMEOUT
            )
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

        for target in TEST_URLS:
            try:
                async with session.get(
                    target,
                    proxy=proxy_url,
                    timeout=timeout,
                    ssl=False,
                    allow_redirects=False,
                ) as response:
                    if 200 <= response.status < 400:
                        speed = round((time.time() - start) * 1000, 1)
                        return True, speed
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
    except asyncio.CancelledError:
        raise
    except Exception:
        pass
    return False, 0.0


ResultCallback = Callable[[str, bool, float], None]


def _split_round_robin(items: List[str], parts: int) -> List[List[str]]:
    """Split items into `parts` chunks of roughly equal size."""
    return [items[i::parts] for i in range(parts)]


def _shard_count(items: List[str], max_threads: int) -> int:
    """How many worker threads to use for `items` (at least one)."""
    return max(1, min(max_threads, len(items)))


class _LoopRegistry:
    """Tracks worker event loops so a stop request made from another thread
    can cancel the checks that are currently in flight."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loops: set = set()

    def register(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loops.add(loop)

    def discard(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loops.discard(loop)

    def cancel_all(self) -> None:
        with self._lock:
            loops = list(self._loops)
        for loop in loops:
            try:
                loop.call_soon_threadsafe(self._cancel_tasks, loop)
            except RuntimeError:
                pass  # loop already closed

    @staticmethod
    def _cancel_tasks(loop: asyncio.AbstractEventLoop) -> None:
        for task in asyncio.all_tasks(loop):
            task.cancel()


def _thread_entry(coro_factory, registry: _LoopRegistry):
    """Worker thread body: run one coroutine on a fresh event loop."""

    async def runner():
        loop = asyncio.get_running_loop()
        registry.register(loop)
        try:
            return await coro_factory()
        finally:
            registry.discard(loop)

    try:
        return asyncio.run(runner())
    except asyncio.CancelledError:
        return None
    except Exception:
        return None


def _watch_stop(stop_event, done_event, registry: _LoopRegistry) -> None:
    """Daemon thread: cancels in-flight checks once stop_event is set."""
    while not done_event.wait(0.25):
        if stop_event.is_set():
            registry.cancel_all()
            return


async def _tor_shard(
    bridges: List[str],
    proxy_type: str,
    report: ResultCallback,
    stop_event: threading.Event,
) -> None:
    for bridge in bridges:
        if stop_event.is_set():
            return
        try:
            ok, speed = await check_tor_bridge(
                bridge, proxy_type, TOR_BOOTSTRAP_TIMEOUT
            )
        except asyncio.CancelledError:
            raise
        except RuntimeError:
            ok, speed = False, 0.0
        except Exception:
            ok, speed = False, 0.0
        report(bridge, ok, speed)


async def _http_shard(
    proxies: List[str],
    proxy_type: str,
    per_thread: int,
    report: ResultCallback,
    stop_event: threading.Event,
) -> None:
    connector = aiohttp.TCPConnector(
        limit=per_thread * 2,
        ssl=False,
        limit_per_host=per_thread,
        ttl_dns_cache=600,
        keepalive_timeout=30,
        enable_cleanup_closed=True,
    )
    session_timeout = aiohttp.ClientTimeout(
        total=HTTP_CHECK_SESSION_TIMEOUT, connect=HTTP_CHECK_CONNECT_TIMEOUT
    )
    semaphore = asyncio.Semaphore(per_thread)

    async with aiohttp.ClientSession(
        connector=connector, timeout=session_timeout, read_bufsize=8192
    ) as session:

        async def one(proxy: str) -> None:
            if stop_event.is_set():
                return
            async with semaphore:
                if stop_event.is_set():
                    return
                try:
                    ok, speed = await check_proxy(
                        session,
                        proxy,
                        proxy_type,
                        test_url=None,
                        timeout=HTTP_CHECK_REQUEST_TIMEOUT,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    ok, speed = False, 0.0
                report(proxy, ok, speed)

        await asyncio.gather(*(one(p) for p in proxies), return_exceptions=True)


async def _singbox_precheck(
    proxies: List[str],
    proxy_type: str,
    report: ResultCallback,
    stop_event: threading.Event,
) -> List[str]:
    """Mass TCP precheck: drop unreachable hosts before spending a sing-box
    process on them. Returns links that survived (in arbitrary order)."""
    semaphore = asyncio.Semaphore(SINGBOX_PRECHECK_CONCURRENT)
    alive: List[str] = []

    async def one(proxy: str) -> None:
        if stop_event.is_set():
            return
        if proxy_type not in TCP_PRECHECK_TYPES:
            alive.append(proxy)
            return
        server_host, server_port = get_link_server(proxy, proxy_type)
        if not server_host or not server_port:
            # Unparseable link: let the full check report it dead.
            alive.append(proxy)
            return
        async with semaphore:
            if stop_event.is_set():
                return
            try:
                pre_ok, _ = await tcp_precheck(server_host, server_port)
            except Exception:
                pre_ok = False
        if pre_ok:
            alive.append(proxy)
        else:
            report(proxy, False, 0.0)

    await asyncio.gather(*(one(p) for p in proxies), return_exceptions=True)
    return alive


async def _singbox_shard(
    proxies: List[str],
    proxy_type: str,
    per_thread: int,
    report: ResultCallback,
    stop_event: threading.Event,
) -> None:
    semaphore = asyncio.Semaphore(per_thread)

    async def one(proxy: str) -> None:
        if stop_event.is_set():
            return
        async with semaphore:
            if stop_event.is_set():
                return
            port = get_free_port()
            try:
                result = await asyncio.wait_for(
                    _check_singbox_async(
                        proxy,
                        proxy_type,
                        port,
                        SINGBOX_CHECK_TIMEOUT,
                        skip_precheck=True,
                    ),
                    timeout=SINGBOX_CHECK_TIMEOUT + 5,
                )
                ok, speed = result[2], result[3]
            except asyncio.CancelledError:
                raise
            except Exception:
                ok, speed = False, 0.0
            report(proxy, ok, speed)

    await asyncio.gather(*(one(p) for p in proxies), return_exceptions=True)


def _submit(executor, registry: _LoopRegistry, factories) -> list:
    return [
        executor.submit(_thread_entry, factory, registry) for factory in factories
    ]


def _tor_factories(proxies, proxy_type, report, stop_event, max_workers):
    count = _shard_count(proxies, min(max_workers, TOR_MAX_CONCURRENT))
    return [
        functools.partial(_tor_shard, shard, proxy_type, report, stop_event)
        for shard in _split_round_robin(proxies, count)
        if shard
    ]


def _http_factories(proxies, proxy_type, report, stop_event, max_workers):
    count = _shard_count(proxies, max_workers)
    per_thread = max(1, (HTTP_MAX_CONCURRENT + count - 1) // count)
    return [
        functools.partial(
            _http_shard, shard, proxy_type, per_thread, report, stop_event
        )
        for shard in _split_round_robin(proxies, count)
        if shard
    ]


def run_checks(
    proxies_list: List[str],
    proxy_type: str,
    on_result: ResultCallback | None = None,
    stop_event: threading.Event | None = None,
    threads: int | None = None,
) -> List[Tuple[str, float]]:
    """Parallel checker shared by the CLI and the GUI.

    Runs checks in a pool of OS threads, each thread executing its own
    asyncio event loop, and returns working proxies sorted by latency.

    `on_result(proxy, ok, speed_ms)` is called from worker threads for every
    checked proxy, so callers must synchronize their UI updates themselves.
    Setting `stop_event` cancels in-flight checks and stops dispatching new
    ones; partial results are returned. KeyboardInterrupt does the same.
    """
    if not proxies_list:
        return []

    ptype = proxy_type.upper()
    if ptype in TOR_TYPES:
        dep_error = _check_tor_dependencies(ptype)
        if dep_error:
            raise RuntimeError(dep_error)
    if ptype in SINGBOX_TYPES and not SINGBOX_INSTALLED:
        raise RuntimeError(f"sing-box not found at {SINGBOX_PATH} - run ./setup.sh")

    if stop_event is None:
        stop_event = threading.Event()

    results: List[Tuple[str, float]] = []
    results_lock = threading.Lock()

    def report(proxy: str, ok: bool, speed: float) -> None:
        if ok and speed > 0:
            with results_lock:
                results.append((proxy, speed))
        if on_result is not None:
            try:
                on_result(proxy, ok, speed)
            except Exception:
                pass

    max_workers = threads if threads and threads > 0 else CHECK_THREADS

    done_event = threading.Event()
    registry = _LoopRegistry()
    watcher = threading.Thread(
        target=_watch_stop, args=(stop_event, done_event, registry), daemon=True
    )
    watcher.start()

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="proxy-check"
    )
    futures: list = []
    try:
        if ptype in TOR_TYPES:
            futures = _submit(
                executor,
                registry,
                _tor_factories(proxies_list, ptype, report, stop_event, max_workers),
            )
            concurrent.futures.wait(futures)
        elif ptype in SINGBOX_TYPES:
            precheck_future = executor.submit(
                _thread_entry,
                functools.partial(
                    _singbox_precheck, proxies_list, ptype, report, stop_event
                ),
                registry,
            )
            futures = [precheck_future]
            concurrent.futures.wait(futures)

            if not stop_event.is_set():
                alive = precheck_future.result() or []
                if alive:
                    count = _shard_count(alive, max_workers)
                    per_thread = max(
                        1, (SINGBOX_MAX_CONCURRENT + count - 1) // count
                    )
                    futures += _submit(
                        executor,
                        registry,
                        [
                            functools.partial(
                                _singbox_shard,
                                shard,
                                ptype,
                                per_thread,
                                report,
                                stop_event,
                            )
                            for shard in _split_round_robin(alive, count)
                            if shard
                        ],
                    )
                    concurrent.futures.wait(futures)
        else:
            futures = _submit(
                executor,
                registry,
                _http_factories(proxies_list, ptype, report, stop_event, max_workers),
            )
            concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        stop_event.set()
        registry.cancel_all()
        try:
            concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            pass
    finally:
        done_event.set()
        executor.shutdown(wait=True)
        watcher.join(timeout=1)

    try:
        results.sort(key=lambda x: x[1])
    except Exception:
        pass
    return results
