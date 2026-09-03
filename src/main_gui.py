import asyncio
import threading
import time
from datetime import datetime
from typing import List, Tuple

import aiohttp
import customtkinter as ctk

from config import (
    DEFAULT_LIMITS,
    DEFAULT_WORKERS,
    PROTOCOLS,
    SINGBOX_INSTALLED,
    SINGBOX_PATH,
    get_proxy_sources,
)
from core import check_proxy, load_proxies_from_sources

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# Gruvbox palette
GRUV_BG = "#1d2021"
GRUV_BG_2 = "#282828"
GRUV_BG_3 = "#3c3836"
GRUV_FG = "#ebdbb2"
GRUV_FG_DIM = "#a89984"
GRUV_GREEN = "#8ec07c"
GRUV_BLUE = "#458588"
GRUV_YELLOW = "#d79921"
GRUV_RED = "#cc241d"

ACCENT_HOVER = ("#458588", "#83a598")
DIM = GRUV_FG_DIM


class SidebarFrame(ctk.CTkFrame):
    def __init__(self, master, on_start, on_stop, on_save, **kwargs):
        super().__init__(master, corner_radius=0, fg_color=GRUV_BG_2, **kwargs)
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_save = on_save
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(14, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(28, 0), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="PROXY SNIFFER",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=GRUV_GREEN,
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="Fast proxy speed tester",
            font=ctk.CTkFont(size=11),
            text_color=DIM,
            anchor="w",
        ).grid(row=1, column=0, sticky="w")

        ctk.CTkLabel(
            self,
            text="Protocol",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
            text_color=GRUV_FG_DIM,
        ).grid(row=4, column=0, padx=20, pady=(20, 6), sticky="w")

        self.protocol_var = ctk.StringVar(value="VLESS")
        self.protocol_menu = ctk.CTkOptionMenu(
            self,
            variable=self.protocol_var,
            values=PROTOCOLS,
            width=220,
            height=38,
            corner_radius=8,
            dropdown_font=ctk.CTkFont(size=12),
            fg_color=GRUV_BG_3,
            button_color=GRUV_BLUE,
            button_hover_color=ACCENT_HOVER,
            dropdown_fg_color=GRUV_BG_3,
            dropdown_hover_color=GRUV_BLUE,
            command=self._on_protocol_change,
        )
        self.protocol_menu.grid(row=5, column=0, padx=20, pady=(0, 10))

        ctk.CTkLabel(
            self,
            text="Proxy Limit",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
            text_color=GRUV_FG_DIM,
        ).grid(row=7, column=0, padx=20, pady=(0, 6), sticky="w")

        self.limit_entry = ctk.CTkEntry(
            self,
            placeholder_text="500",
            width=220,
            height=38,
            corner_radius=8,
            border_width=1,
            fg_color=GRUV_BG_3,
            border_color=GRUV_BG_3,
            placeholder_text_color=GRUV_FG_DIM,
        )
        self.limit_entry.grid(row=8, column=0, padx=20, pady=(0, 10))
        self.limit_entry.insert(0, "500")

        ctk.CTkFrame(self, height=1, fg_color=GRUV_BG_3).grid(
            row=9, column=0, padx=20, pady=(10, 10), sticky="ew"
        )

        self.start_btn = ctk.CTkButton(
            self,
            text="START",
            command=self.on_start,
            height=44,
            width=220,
            corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=GRUV_GREEN,
            hover_color=("#689d6a", "#689d6a"),
            text_color="#1d2021",
        )
        self.start_btn.grid(row=10, column=0, padx=20, pady=(5, 5))

        self.stop_btn = ctk.CTkButton(
            self,
            text="STOP",
            command=self.on_stop,
            height=44,
            width=220,
            corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=GRUV_RED,
            hover_color=("#9d0006", "#9d0006"),
            text_color="#ebdbb2",
            state="disabled",
        )
        self.stop_btn.grid(row=11, column=0, padx=20, pady=(5, 10))

        ctk.CTkFrame(self, height=1, fg_color=GRUV_BG_3).grid(
            row=12, column=0, padx=20, pady=(10, 10), sticky="ew"
        )

        self.save_btn = ctk.CTkButton(
            self,
            text="Save Results",
            command=self.on_save,
            height=38,
            width=220,
            corner_radius=8,
            font=ctk.CTkFont(size=13),
            fg_color=GRUV_BLUE,
            hover_color=ACCENT_HOVER,
            text_color="#ebdbb2",
            state="disabled",
        )
        self.save_btn.grid(row=13, column=0, padx=20, pady=(5, 10))

        self.singbox_label = ctk.CTkLabel(
            self,
            text=f"sing-box: {'OK' if SINGBOX_INSTALLED else 'not found'}",
            font=ctk.CTkFont(size=12),
            text_color=GRUV_GREEN if SINGBOX_INSTALLED else GRUV_RED,
            anchor="center",
        )
        self.singbox_label.grid(row=15, column=0, padx=20, pady=(0, 20), sticky="ew")

    def _on_protocol_change(self, protocol):
        default = DEFAULT_LIMITS.get(protocol, 500)
        self.limit_entry.delete(0, "end")
        self.limit_entry.insert(0, str(default))

    def get_protocol(self):
        return self.protocol_var.get()

    def get_limit(self):
        try:
            return int(self.limit_entry.get())
        except ValueError:
            return DEFAULT_LIMITS.get(self.protocol_var.get(), 500)

    def set_running(self, running):
        state = "disabled" if running else "normal"
        self.start_btn.configure(state=state)
        self.stop_btn.configure(state="normal" if running else "disabled")
        self.protocol_menu.configure(state=state)
        self.limit_entry.configure(state=state)

    def set_results_available(self, available):
        self.save_btn.configure(state="normal" if available else "disabled")


class ContentFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, corner_radius=0, fg_color=GRUV_BG, **kwargs)
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(20, 12), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Results",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=GRUV_FG,
        ).grid(row=0, column=0, sticky="w")

        self.stats_label = ctk.CTkLabel(
            header,
            text="Ready",
            font=ctk.CTkFont(size=13),
            text_color=DIM,
        )
        self.stats_label.grid(row=0, column=1, sticky="e")

        self.table_frame = ctk.CTkScrollableFrame(
            self,
            corner_radius=8,
            border_width=1,
            border_color=GRUV_BG_3,
            fg_color=GRUV_BG_2,
        )
        self.table_frame.grid(row=1, column=0, padx=20, pady=5, sticky="nsew")
        self.table_frame.grid_columnconfigure(1, weight=1)

        self.table_header = ctk.CTkFrame(self.table_frame, fg_color=GRUV_BG_3, corner_radius=6)
        self.table_header.grid(
            row=0, column=0, columnspan=3, sticky="ew", padx=2, pady=(0, 6)
        )
        self.table_header.grid_columnconfigure(1, weight=1)

        for i, text in enumerate(["#", "Proxy", "Speed"]):
            ctk.CTkLabel(
                self.table_header,
                text=text,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=GRUV_YELLOW,
                width=[40, 0, 90][i],
                anchor="w" if i < 2 else "e",
                padx=6,
            ).grid(row=0, column=i, padx=(4, 4), pady=8, sticky="ew" if i == 1 else "w")

        self.table_rows_frame = ctk.CTkFrame(self.table_frame, fg_color="transparent")
        self.table_rows_frame.grid(row=1, column=0, columnspan=3, sticky="ew")
        self.table_rows_frame.grid_columnconfigure(1, weight=1)

        progress_frame = ctk.CTkFrame(self, fg_color="transparent")
        progress_frame.grid(row=2, column=0, padx=20, pady=(14, 4), sticky="ew")
        progress_frame.grid_columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(
            progress_frame, height=14, corner_radius=6,
            progress_color=GRUV_GREEN,
            fg_color=GRUV_BG_3,
        )
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 12))

        self.progress_label = ctk.CTkLabel(
            progress_frame,
            text="0%",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=50,
            text_color=GRUV_GREEN,
        )
        self.progress_label.grid(row=0, column=1)

        self.status_label = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=DIM,
            anchor="w",
        )
        self.status_label.grid(row=3, column=0, padx=20, pady=(2, 6), sticky="ew")

        ctk.CTkLabel(
            self,
            text="Log",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=GRUV_FG,
            anchor="w",
        ).grid(row=4, column=0, padx=20, pady=(14, 6), sticky="w")

        self.log_textbox = ctk.CTkTextbox(
            self,
            height=160,
            corner_radius=6,
            border_width=1,
            border_color=GRUV_BG_3,
            fg_color=GRUV_BG_2,
            text_color=GRUV_FG,
            font=ctk.CTkFont(family="Consolas", size=11),
        )
        self.log_textbox.grid(row=5, column=0, padx=20, pady=(0, 16), sticky="ew")

    def clear_results(self):
        for widget in self.table_rows_frame.winfo_children():
            widget.destroy()

    def add_result_row(self, index, proxy, speed):
        row_frame = ctk.CTkFrame(
            self.table_rows_frame,
            fg_color="transparent",
        )
        row_frame.grid(row=index, column=0, columnspan=3, sticky="ew", pady=1)
        row_frame.grid_columnconfigure(1, weight=1)

        bg = (GRUV_BG_3, GRUV_BG_3) if index % 2 == 0 else "transparent"

        ctk.CTkLabel(
            row_frame,
            text=f"{index:02d}",
            font=ctk.CTkFont(size=11),
            width=40,
            anchor="w",
            fg_color=bg,
            corner_radius=3,
            text_color=DIM,
        ).grid(row=0, column=0, padx=(4, 4), sticky="w", pady=1)

        display = proxy if len(proxy) <= 75 else proxy[:72] + "..."
        ctk.CTkLabel(
            row_frame,
            text=display,
            font=ctk.CTkFont(family="Consolas", size=11),
            anchor="w",
            fg_color=bg,
            corner_radius=3,
            text_color=GRUV_FG,
        ).grid(row=0, column=1, padx=(4, 4), sticky="ew", pady=1)

        ctk.CTkLabel(
            row_frame,
            text=f"{speed}ms",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=GRUV_GREEN,
            width=90,
            anchor="e",
            fg_color=bg,
            corner_radius=3,
        ).grid(row=0, column=2, padx=(4, 4), sticky="e", pady=1)

    def update_stats(self, checked, total, working, failed):
        self.stats_label.configure(
            text=f"{checked}/{total}    OK {working}    Fail {failed}"
        )

    def update_progress(self, value, text=""):
        self.progress_bar.set(value)
        self.progress_label.configure(text=f"{int(value * 100)}%")
        if text:
            self.status_label.configure(text=text)

    def log(self, message):
        self.log_textbox.insert("end", message + "\n")
        self.log_textbox.see("end")

    def clear_log(self):
        self.log_textbox.delete("1.0", "end")


class ProxySnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.configure(fg_color=GRUV_BG)

        self.title("PROXY SNIFFER - By Nighty3098")
        self.geometry("1180x780")
        self.minsize(980, 640)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._stop_event = threading.Event()
        self._worker_thread = None
        self._working_results: List[Tuple[str, float]] = []

        self.sidebar = SidebarFrame(
            self,
            on_start=self._on_start,
            on_stop=self._on_stop,
            on_save=self._on_save,
            width=260,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.content = ContentFrame(self)
        self.content.grid(row=0, column=1, sticky="nsew")

        self._set_status("Ready to scan")

    def _set_status(self, text):
        self.after(0, lambda: self.content.update_progress(0, text))

    def _log(self, msg):
        self.after(0, lambda: self.content.log(msg))

    def _update_ui(self, value, checked, total, working, failed):
        def _do():
            self.content.update_progress(
                value, f"{checked}/{total}  OK {working}  Fail {failed}"
            )
            self.content.update_stats(checked, total, working, failed)
        self.after(0, _do)

    def _add_result(self, index, proxy, speed):
        self.after(0, lambda: self.content.add_result_row(index, proxy, speed))

    def _on_start(self):
        self._stop_event.clear()
        self._working_results.clear()

        self.sidebar.set_running(True)
        self.sidebar.set_results_available(False)
        self.content.clear_results()
        self.content.clear_log()
        self.content.update_progress(0, "Starting...")
        self.content.update_stats(0, 0, 0, 0)

        protocol = self.sidebar.get_protocol()
        limit = self.sidebar.get_limit()

        self._worker_thread = threading.Thread(
            target=self._run_worker,
            args=(protocol, limit),
            daemon=True,
        )
        self._worker_thread.start()

    def _on_stop(self):
        self._stop_event.set()
        self._log("Stopping... please wait")

    def _on_save(self):
        if not self._working_results:
            return

        protocol = self.sidebar.get_protocol()
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{protocol.lower()}_gui_{timestamp}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            for proxy, speed in self._working_results:
                f.write(f"{proxy}  # {speed}ms\n")

        self._log(f"Saved {len(self._working_results)} proxies to {filename}")

    def _finish(self):
        def _do():
            self.sidebar.set_running(False)
            if self._working_results:
                self.sidebar.set_results_available(True)
        self.after(0, _do)

    def _run_worker(self, protocol, limit):
        try:
            asyncio.run(self._check_proxies(protocol, limit))
        except Exception as e:
            self._log(f"Error: {e}")
        finally:
            self._finish()

    async def _check_proxies(self, protocol, limit):
        proxy_sources = get_proxy_sources()

        self._log(f"Loading {protocol} proxies...")
        proxies = await load_proxies_from_sources(proxy_sources, protocol, quiet=True)
        proxies = proxies[:limit]
        total = len(proxies)

        if total == 0:
            self._log("No proxies loaded!")
            return

        self._log(f"Loaded {total} {protocol} proxies")

        is_singbox = protocol in ["VMESS", "VLESS", "TROJAN", "HYSTERIA2", "SHADOW_SOCKS"]
        if is_singbox and not SINGBOX_INSTALLED:
            self._log(f"sing-box not found at {SINGBOX_PATH} - using socket fallback")

        working = []
        failed = 0
        checked = 0
        start_time = time.time()

        sem = asyncio.Semaphore(min(8 if is_singbox else DEFAULT_WORKERS * 2, 32))
        test_url = "https://httpbin.org/ip"

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                limit=200,
                ssl=False,
                limit_per_host=50,
                ttl_dns_cache=600,
            ),
            timeout=aiohttp.ClientTimeout(total=10, connect=3),
        ) as session:

            async def check_one(idx, proxy):
                nonlocal checked, failed
                if self._stop_event.is_set():
                    return

                async with sem:
                    ok, speed = False, 0.0
                    try:
                        ok, speed = await check_proxy(
                            session, proxy, protocol,
                            test_url=test_url, timeout=6,
                        )
                    except Exception:
                        pass

                    checked += 1
                    if ok and speed > 0:
                        working.append((proxy, speed))
                        self._log(f"  {proxy[:65]}  {speed}ms")
                        self._add_result(len(working), proxy, speed)
                    else:
                        failed += 1

                    elapsed = time.time() - start_time
                    value = checked / total
                    eta = int((elapsed / checked) * (total - checked)) if checked > 0 else 0
                    eta_str = f"ETA: {eta // 60}m {eta % 60}s" if eta > 0 else ""
                    self._update_ui(value, checked, total, len(working), failed)

            self._log(f"Checking {total} {protocol} proxies...")

            tasks = [
                asyncio.create_task(check_one(i, p))
                for i, p in enumerate(proxies)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        working.sort(key=lambda x: x[1])
        self._working_results = working

        elapsed = time.time() - start_time
        self._log(
            f"Done! Found {len(working)}/{total} working proxies in {elapsed:.1f}s"
        )


def main():
    app = ProxySnifferApp()
    app.mainloop()


if __name__ == "__main__":
    main()
