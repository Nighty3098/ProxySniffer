<img src="imgs/i_3.png" width="20%" align="right" />

<div width="70%" align="left">

<br />

<h3>ProxySniffer</h3>

Testing and sorting proxies by speed. Supports HTTP, HTTPS, SOCKS4, SOCKS5, VLESS, VMESS, Trojan, Hysteria2, ShadowSocks, MTProto and Tor bridges (obfs4, webtunnel, snowflake).

</div>

<br />
<br />
<br />
<br />
<br />
<br />

![alt text](imgs/1.png)

![alt text](imgs/2.png)

![alt text](imgs/3.png)

## Features

- Load proxy lists from multiple sources
- Asynchronous multi-threaded testing
- Supported protocols: HTTP, HTTPS, SOCKS4, SOCKS5, VLESS, VMESS, Trojan, Hysteria2, ShadowSocks, MTProto, Tor bridges (obfs4/webtunnel/snowflake)
- Tor bridges are verified by a full Tor bootstrap to 100% (not just TCP)
- Automatic detection of CPU core count
- Output working proxies sorted by speed
- Save results to a file

## Requirements

- Python 3.9+
- Linux (tested on Arch/Ubuntu/Debian)
- sing-box binary (for testing VLESS/VMESS/Trojan/Hysteria2/SS, auto-installed by setup.sh)
- Tor Expert Bundle + lyrebird (for testing Tor bridges, auto-installed by setup.sh, Linux x86_64 only)
- snowflake-client binary (for testing snowflake bridges, auto-installed by setup.sh, Linux x86_64 only)

## Installation

### Quick Start (auto-installer)

```bash
git clone https://github.com/He6vyL0v3/ProxySniffer
cd ProxySniffer
./setup.sh
```

### Manual Installation

#### 1. Clone the repository

```bash
git clone https://github.com/He6vyL0v3/ProxySniffer
cd ProxySniffer
```

#### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

#### 3. Download sing-box

```bash
mkdir -p /tmp/sing-box-1.13.4-linux-amd64
cd /tmp/sing-box-1.13.4-linux-amd64
wget -q https://github.com/SagerNet/sing-box/releases/download/v1.13.4/sing-box-1.13.4-linux-amd64.tar.gz -O sing-box.tar.gz
tar -xzf sing-box.tar.gz
mv sing-box-1.13.4-linux-amd64/sing-box ./sing-box
chmod +x ./sing-box
rm sing-box.tar.gz
```

#### 4. Download Tor Expert Bundle (for Tor bridge testing, Linux x86_64)

```bash
TOR_BUNDLE_VERSION="15.0.23"
cd /tmp
curl -fL -o tor-expert-bundle.tar.gz "https://dist.torproject.org/torbrowser/${TOR_BUNDLE_VERSION}/tor-expert-bundle-linux-x86_64-${TOR_BUNDLE_VERSION}.tar.gz"
mkdir -p "tor-expert-bundle-${TOR_BUNDLE_VERSION}-linux-x86_64/bundle"
tar -xzf tor-expert-bundle.tar.gz -C "tor-expert-bundle-${TOR_BUNDLE_VERSION}-linux-x86_64/bundle" tor data docs
```

The checker expects `tor-client` wrapper + `tor/pluggable_transports/lyrebird` inside that directory (setup.sh creates the wrapper automatically).

#### 5. Download snowflake-client (for snowflake bridge testing, Linux x86_64)

```bash
mkdir -p /tmp/snowflake-2.14.1-linux-x86_64
curl -fL -o /tmp/snowflake-2.14.1-linux-x86_64/snowflake-client \
  https://archive.torproject.org/tor-package-archive/snowflake/2.14.1/client_linux_amd64
chmod +x /tmp/snowflake-2.14.1-linux-x86_64/snowflake-client
```

Alternatively install it from your distro: `sudo apt install snowflake-client` (the checker looks in `/usr/bin` first).

> Note: binaries under `/tmp` are wiped on reboot — just re-run `./setup.sh` to restore them.

#### 6. Run

```bash
cd src
python3 main.py
```

## Usage

```
=================================================================
           PROXY CHECKER TOOL - By Nighty3098
=================================================================
[*] CPU Cores: 12 | Workers: 24

[1] HTTP Proxy
[2] HTTPS Proxy
[3] SOCKS4 Proxy
[4] SOCKS5 Proxy
[5] MTPROTO Proxy
[6] HYSTERIA2 Proxy
[7] SHADOW_SOCKS Proxy
[8] TROJAN Proxy
[9] VMESS Proxy
[10] VLESS Proxy
[11] TOR OBFS4 Proxy
[12] TOR WEBTUNNEL Proxy
[13] TOR SNOWFLAKE Proxy
[0] Exit

[SELECT OPTION] >
```

Select the proxy type (1-13) and specify the number of proxies to test.

### Default Limits

- HTTP/HTTPS/SOCKS4/SOCKS5: 2000 proxies
- VLESS/VMESS/Trojan/Hysteria2/ShadowSocks/MTProto: 500 proxies
- TOR_OBFS4/TOR_WEBTUNNEL/TOR_SNOWFLAKE: 100 bridges

### Recommended Settings

For HTTP/SOCKS proxies, it is recommended to test 1000-3000 proxies at a time.

For VLESS/VMESS/Trojan, do not exceed 500, as testing requires launching a separate sing-box process for each proxy.

For Tor bridges, do not exceed 100: each bridge launches a separate `tor` process that bootstraps to 100% (up to 90s per bridge, max 4 in parallel). 100 bridges can take ~35 minutes in the worst case.

## GUI Mode

ProxySniffer also has a graphical interface using CustomTkinter.

### Run GUI

```bash
cd src
python3 main_gui.py
```

### GUI Features

- Modern dark/light theme (follows system settings)
- All 13 protocols supported (including Tor bridges)
- Real-time progress bar with ETA
- Scrolling log with live proxy check results
- Results table sorted by speed
- One-click save to file

## Project Structure

```
ProxySniffer/
├── src/
│   ├── main.py          # CLI entry point
│   ├── main_gui.py      # GUI entry point
│   ├── config.py        # Configuration
│   ├── core.py          # Core checking logic
│   ├── checker.py       # Protocol checkers
│   ├── fetcher.py       # Proxy downloader
│   ├── parsers.py       # Link parsers
│   ├── links.py         # Proxy sources
│   └── utils.py         # Utilities
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## Protocols and Testing Methods

| Protocol      | Testing Method                                  | Requires               |
| ------------- | ----------------------------------------------- | ---------------------- |
| HTTP/HTTPS    | aiohttp directly                                | No                     |
| SOCKS4/SOCKS5 | aiohttp via proxy                               | No                     |
| VLESS         | end-to-end via sing-box (real HTTPS request through the tunnel) | sing-box |
| VMESS         | sing-box                                        | sing-box               |
| Trojan        | sing-box                                        | sing-box               |
| Hysteria2     | sing-box                                        | sing-box               |
| ShadowSocks   | sing-box                                        | sing-box               |
| MTProto       | TCP handshake                                   | Partial                |
| TOR_OBFS4     | full Tor bootstrap to 100% (TCP precheck first) | tor + lyrebird         |
| TOR_WEBTUNNEL | full Tor bootstrap to 100% (TCP precheck first) | tor + lyrebird         |
| TOR_SNOWFLAKE | full Tor bootstrap to 100%                      | tor + snowflake-client |

### VLESS Verification

VLESS links are verified end-to-end: sing-box connects through the proxy and performs a real HTTPS request. A link is reported as working only if actual traffic goes through the tunnel — a TCP/TLS handshake alone is not enough. A fast TCP precheck is used only to discard unreachable hosts.

VLESS links that sing-box cannot faithfully reproduce are intentionally reported as not working instead of being counted as live (this avoids false positives):

- transports `xhttp`/`splithttp`, `kcp`/`mkcp`, `http3`
- `tcp` with `headerType=http` obfuscation
- encrypted VLESS (`encryption` other than `none`)
- REALITY without `pbk`, and unsupported `flow` values

## Subscription Filtering and Deduplication

Downloaded sources are frequently mixed, so before checking:

- every line must match the selected protocol group and parse successfully — otherwise it is dropped: `vless://`, `vmess://`, `trojan://`, `hysteria2://`, `ss://` links, `t.me/proxy` links for MTProto, `obfs4`/`webtunnel`/`snowflake` bridge lines for Tor, `http(s)://` / `socks4(5)://` lines and bare `host:port` entries for the corresponding HTTP/SOCKS group;
- the remaining entries are deduplicated by config identity (server, port, credentials, transport parameters). The same proxy with a different remark, query-parameter order or URL-encoding is checked only once.

The CLI prints how many foreign links and duplicates were removed; the GUI applies the same filtering silently.

## Parallel Checking

Both the CLI and the GUI use the same threaded checking engine (`core.run_checks`):

- a pool of OS threads, each running its own asyncio event loop;
- for HTTP/HTTPS/SOCKS/MTProto the total concurrency is `HTTP_MAX_CONCURRENT` (checked via aiohttp);
- for VLESS/VMESS/Trojan/Hysteria2/ShadowSocks a mass TCP precheck first filters unreachable hosts (skipped for hysteria2, which is QUIC/UDP), then up to `SINGBOX_MAX_CONCURRENT` sing-box processes run in parallel;
- `on_result` callbacks come from worker threads: the CLI serializes rich output with a lock, the GUI marshals updates to the Tk thread via `after()`;
- a `threading.Event` stop request cancels in-flight checks (CLI: Ctrl+C, GUI: Stop button) and returns partial results.

Concurrency caps are configured in `config.py` (`CHECK_THREADS`, `HTTP_MAX_CONCURRENT`, `SINGBOX_MAX_CONCURRENT`, `TOR_MAX_CONCURRENT`).

## Troubleshooting

### Error "sing-box not found"

VLESS/VMESS/Trojan/Hysteria2/ShadowSocks are verified only through sing-box — there is no socket fallback. Run `./setup.sh` to download sing-box to `/tmp/sing-box-1.13.4-linux-amd64/sing-box`.

### Slow VLESS/VMESS Testing

This is normal - a separate sing-box process is started for each proxy. Unreachable hosts are dropped by a fast mass TCP precheck so they do not occupy sing-box processes, and checks are spread across `CHECK_THREADS` worker threads. Limit the number of proxies to 500.

### Error "tor not found" / "lyrebird not found"

Run `./setup.sh` — it downloads the Tor Expert Bundle (Linux x86_64) to `/tmp/tor-expert-bundle-15.0.23-linux-x86_64`.

### Error "snowflake-client not found"

Run `./setup.sh` (downloads the official Tor Project build), or install it from your distro: `sudo apt install snowflake-client`.

### Slow Tor bridge testing

This is normal - each bridge launches a separate `tor` process that bootstraps the whole Tor circuit up to 100% (up to 90s per bridge, max 4 in parallel). Dead IPs are skipped by a fast TCP precheck (~1.5s), but a full list of 100 bridges can still take tens of minutes.

### HTTP Proxy Testing Not Working

```bash
# Check that the proxy works
curl -x http://IP:PORT https://httpbin.org/ip
```
