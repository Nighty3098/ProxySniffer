import asyncio
import os
import time
from datetime import datetime
from typing import List, Tuple

import aiohttp
from colorama import Fore, init
from rich import print as rprint
from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn)
from rich.table import Table

console = Console()

init(autoreset=True)

from links import proxy_HTTP, proxy_HTTPS, proxy_SOCKS4, proxy_SOCKS5

proxy_sources = {
    "HTTP": proxy_HTTP,
    "HTTPS": proxy_HTTPS,
    "SOCKS4": proxy_SOCKS4,
    "SOCKS5": proxy_SOCKS5,
}

proxy_mapping = {1: "HTTP", 2: "HTTPS", 3: "SOCKS4", 4: "SOCKS5"}


def parse_proxy(proxy: str) -> str:
    proxy = proxy.strip()
    
    for prefix in ("http://", "https://", "socks4://", "socks5://", "socks4h://", "socks5h://"):
        if proxy.lower().startswith(prefix):
            return proxy[len(prefix):].strip()
    
    return proxy


async def check_proxy(session, proxy: str, proxy_type: str, test_url: str = "https://httpbin.org/ip", timeout: int = 10) -> Tuple[bool, float]:
    try:
        start = time.time()
        
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

        async with session.get(test_url, proxy=proxy_url, timeout=timeout, ssl=False) as response:
            if response.status == 200:
                speed = round((time.time() - start) * 1000, 1)
                return True, speed
    except:
        pass
    return False, 0.0


async def check_proxies_async(proxies_list: List[str], proxy_type: str, max_concurrent: int = 500):
    working = []
    connector = aiohttp.TCPConnector(limit=500, ssl=False, limit_per_host=50, ttl_dns_cache=300)

    test_url = "https://httpbin.org/ip"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"[green]Checking {proxy_type} proxies...", total=len(proxies_list))

        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=8, connect=3)) as session:
            semaphore = asyncio.Semaphore(max_concurrent)

            async def bounded_check(p):
                async with semaphore:
                    ok, speed = await check_proxy(session, p, proxy_type, test_url=test_url, timeout=5)
                    return p, ok, speed

            tasks = [bounded_check(p) for p in proxies_list]

            for coro in asyncio.as_completed(tasks):
                proxy, ok, speed = await coro
                progress.advance(task)
                if ok and speed > 0:
                    working.append((proxy, speed))
                    console.print(f"[green]✓[/green] [cyan]{proxy}[/cyan] [magenta]{speed}ms[/magenta]")
                else:
                    console.print(f"[red]✗[/red] [dim]{proxy}[/dim]")

    working.sort(key=lambda x: x[1])
    return working


async def fetch_proxies(url: str) -> List[str]:
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    proxies = []
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if ':' in line:
                            if any(line.lower().startswith(p) for p in ("http://", "https://", "socks4://", "socks5://", "socks4h://", "socks5h://")):
                                proxies.append(line)
                            elif line.count(':') == 1:
                                proxies.append(line)
                    return proxies
    except Exception:
        pass
    return []


async def load_proxies_from_sources(proxy_type: str) -> List[str]:
    sources = proxy_sources.get(proxy_type.upper(), [])
    all_proxies: set = set()

    console.print(f"[cyan][*] Downloading {proxy_type} proxies from {len(sources)} sources...[/cyan]")

    tasks = [fetch_proxies(url) for url in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            all_proxies.update(result)

    unique_proxies = list(all_proxies)
    console.print(f"[green][+] Loaded {len(unique_proxies)} unique {proxy_type} proxies[/green]")
    return unique_proxies


def save_working_proxies(working: List[Tuple], proxy_type: str):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{proxy_type.lower()}_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        for proxy, speed in working:
            f.write(f"{proxy}  # {speed}ms\n")

    console.print(f"[green][+] Saved {len(working)} working proxies to {filename}[/green]")


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


def main_menu():
    console.print("")
    console.print("[1] HTTP Proxy")
    console.print("[2] HTTPS Proxy")
    console.print("[3] SOCKS4 Proxy")
    console.print("[4] SOCKS5 Proxy")
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
        elif choice not in [1, 2, 3, 4]:
            console.print("\n[red][!] Invalid option![/red]")
            time.sleep(1)
            continue

        proxy_type = proxy_mapping[choice]

        try:
            print_banner()
            list_limit = int(console.input("\n[yellow][PROXY LIMIT] > [/yellow]"))
        except ValueError:
            console.print("\n[red][!] Invalid number![/red]")
            time.sleep(1)
            continue

        print_banner()
        console.print(f"[cyan][*] Loading {proxy_type} proxies...[/cyan]")
        proxies = await load_proxies_from_sources(proxy_type)

        if not proxies:
            console.print(f"[red][!] No proxies loaded from sources![/red]")
            time.sleep(2)
            continue

        proxies = proxies[:list_limit]
        console.print(f"[green][+] Loaded {len(proxies)} proxies[/green]")

        console.print(f"[green][*] Checking {proxy_type} proxies...[/green]")
        working = await check_proxies_async(proxies, proxy_type, max_concurrent=80)

        console.print(f"\n[green][+] Found {len(working)} working proxies[/green]")

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
            console.print(f"[bold cyan]WORKING PROXIES (IP:PORT | RESPONSE TIME)[/bold cyan]")
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
