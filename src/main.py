import asyncio
import os
import time
from datetime import datetime
from typing import List, Tuple

from colorama import Fore, init
from rich.console import Console
from rich.table import Table

from config import (
    CPU_CORES,
    DEFAULT_WORKERS,
    SINGBOX_INSTALLED,
    SINGBOX_PATH,
    proxy_mapping,
)
from core import check_all_parallel, load_proxies_from_sources
from links import (
    proxy_HTTP,
    proxy_HTTPS,
    proxy_HYSTERIA2,
    proxy_MTPROTO,
    proxy_SHADOW_SOCKS,
    proxy_SOCKS4,
    proxy_SOCKS5,
    proxy_TROJAN,
    proxy_VLESS,
    proxy_VMESS,
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

init(autoreset=True)

console = Console()


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
        proxies = await load_proxies_from_sources(proxy_sources, proxy_type)

        if (
            proxy_type in ["VLESS", "VMESS", "TROJAN", "HYSTERIA2", "SHADOW_SOCKS"]
            and not SINGBOX_INSTALLED
        ):
            console.print(
                f"[red][!] WARNING: sing-box not found at {SINGBOX_PATH}[/red]"
            )
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
            console.print(
                f"\n[cyan]Found {len(working)} working proxies before stop[/cyan]"
            )

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
