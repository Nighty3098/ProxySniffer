#!/bin/bash

set -e

echo "========================================="
echo "  ProxySniffer - Auto Setup"
echo "========================================="

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Checking Python version...${NC}"
python3 --version || { echo -e "${RED}Python 3 not found! Please install Python 3.9+${NC}"; exit 1; }

echo -e "${YELLOW}Setup venv...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "${YELLOW}Installing Python dependencies...${NC}"
cd "$(dirname "$0")"
pip install -r requirements.txt

echo -e "${YELLOW}Installing optional speedup packages...${NC}"
pip install aiodns cchardet Brotli 2>/dev/null || echo -e "${YELLOW}Optional packages skipped${NC}"

SINGBOX_DIR="/tmp/sing-box-1.13.4-linux-amd64"
SINGBOX_PATH="$SINGBOX_DIR/sing-box"

if [ ! -f "$SINGBOX_PATH" ]; then
    echo -e "${YELLOW}Downloading sing-box...${NC}"
    mkdir -p "$SINGBOX_DIR"
    cd "$SINGBOX_DIR"

    VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name"' | cut -d'"' -f4 || echo "v1.13.4")

    echo -e "${GREEN}Downloading $VERSION...${NC}"

    wget -q "https://github.com/SagerNet/sing-box/releases/download/${VERSION}/sing-box-${VERSION#v}-linux-amd64.tar.gz" -O sing-box.tar.gz

    tar -xzf sing-box.tar.gz
    mv "sing-box-${VERSION#v}-linux-amd64/sing-box" "$SINGBOX_PATH"
    chmod +x "$SINGBOX_PATH"

    rm sing-box.tar.gz

    echo -e "${GREEN}sing-box installed successfully!${NC}"
else
    echo -e "${GREEN}sing-box already installed${NC}"
fi

TOR_BUNDLE_VERSION="15.0.23"
TOR_BUNDLE_DIR="$(dirname "$SINGBOX_DIR")/tor-expert-bundle-${TOR_BUNDLE_VERSION}-linux-x86_64"
TOR_PATH="$TOR_BUNDLE_DIR/tor-client"
LYREBIRD_PATH="$TOR_BUNDLE_DIR/tor/pluggable_transports/lyrebird"

(
    set -e
    if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
        echo -e "${RED}Tor Expert Bundle requires Linux x86_64${NC}"
        exit 1
    fi

    if [ ! -e "$TOR_BUNDLE_DIR" ] && [ ! -L "$TOR_BUNDLE_DIR" ]; then
        echo -e "${YELLOW}Downloading Tor Expert Bundle $TOR_BUNDLE_VERSION...${NC}"
        TOR_STAGE=$(mktemp -d "$(dirname "$SINGBOX_DIR")/tor-setup.XXXXXXXX")
        trap 'rm -rf -- "$TOR_STAGE"' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        TOR_ARCHIVE="$TOR_STAGE/tor-expert-bundle.tar.gz"
        TOR_SHA256="08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985"
        TOR_CURL_ARGS=()
        if [ -n "${TOR_DOWNLOAD_PROXY:-}" ]; then
            TOR_CURL_ARGS=(--proxy "$TOR_DOWNLOAD_PROXY" --noproxy "")
        fi
        curl --fail --location --show-error --silent --retry 2 \
            --connect-timeout 15 --max-time 300 --proto '=https' --proto-redir '=https' \
            "${TOR_CURL_ARGS[@]}" \
            "https://dist.torproject.org/torbrowser/$TOR_BUNDLE_VERSION/tor-expert-bundle-linux-x86_64-$TOR_BUNDLE_VERSION.tar.gz" \
            --output "$TOR_ARCHIVE"
        sha256sum --check <<< "$TOR_SHA256  $TOR_ARCHIVE"
        mkdir "$TOR_STAGE/bundle"
        tar --extract --gzip --file "$TOR_ARCHIVE" --directory "$TOR_STAGE/bundle" \
            --no-same-owner --no-same-permissions tor data docs
        chmod u+x "$TOR_STAGE/bundle/tor/tor" \
            "$TOR_STAGE/bundle/tor/pluggable_transports/lyrebird"
        cat > "$TOR_STAGE/bundle/tor-client" <<'TOR_LAUNCHER'
#!/bin/sh
TOR_LIB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/tor" && pwd) || exit 1
export LD_LIBRARY_PATH="$TOR_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$TOR_LIB_DIR/tor" "$@"
TOR_LAUNCHER
        chmod u+x "$TOR_STAGE/bundle/tor-client"
        "$TOR_STAGE/bundle/tor-client" --version
        "$TOR_STAGE/bundle/tor/pluggable_transports/lyrebird" -version
        mv -T -- "$TOR_STAGE/bundle" "$TOR_BUNDLE_DIR"
        echo -e "${GREEN}Tor Expert Bundle installed successfully!${NC}"
    else
        if [ -L "$TOR_BUNDLE_DIR" ] || [ ! -O "$TOR_BUNDLE_DIR" ] || \
            [ ! -x "$TOR_PATH" ] || [ ! -x "$LYREBIRD_PATH" ]; then
            echo -e "${RED}Unsafe or incomplete Tor installation at $TOR_BUNDLE_DIR; inspect it before retrying${NC}"
            exit 1
        fi
        "$TOR_PATH" --version
        "$LYREBIRD_PATH" -version
        echo -e "${GREEN}Tor Expert Bundle already installed${NC}"
    fi
)

echo "TOR_PATH=$TOR_PATH"
echo "LYREBIRD_PATH=$LYREBIRD_PATH"

SNOWFLAKE_VERSION="2.14.1"
SNOWFLAKE_DIR="/tmp/snowflake-${SNOWFLAKE_VERSION}-linux-x86_64"
SNOWFLAKE_BIN="$SNOWFLAKE_DIR/snowflake-client"

if [ -x "$SNOWFLAKE_BIN" ]; then
    echo -e "${GREEN}snowflake-client already installed${NC}"
elif command -v snowflake-client >/dev/null 2>&1; then
    echo -e "${GREEN}snowflake-client found in PATH ($(command -v snowflake-client))${NC}"
else
    if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
        echo -e "${RED}Prebuilt snowflake-client is available for Linux x86_64 only${NC}"
    else
        echo -e "${YELLOW}Downloading snowflake-client $SNOWFLAKE_VERSION (official Tor Project build)...${NC}"
        mkdir -p "$SNOWFLAKE_DIR"
        SNOWFLAKE_URL="https://archive.torproject.org/tor-package-archive/snowflake/${SNOWFLAKE_VERSION}/client_linux_amd64"
        SNOWFLAKE_CURL_ARGS=()
        if [ -n "${TOR_DOWNLOAD_PROXY:-}" ]; then
            SNOWFLAKE_CURL_ARGS=(--proxy "$TOR_DOWNLOAD_PROXY" --noproxy "")
        fi
        curl --fail --location --show-error --silent --retry 2 \
            --connect-timeout 15 --max-time 300 --proto '=https' --proto-redir '=https' \
            "${SNOWFLAKE_CURL_ARGS[@]}" \
            "$SNOWFLAKE_URL" --output "$SNOWFLAKE_BIN"
        chmod +x "$SNOWFLAKE_BIN"
        "$SNOWFLAKE_BIN" -h >/dev/null 2>&1
        echo -e "${GREEN}snowflake-client installed successfully!${NC}"
    fi
fi

echo "SNOWFLAKE_BIN=$SNOWFLAKE_BIN"

echo -e "\n${GREEN}========================================="
echo "  Setup Complete!"
echo "=========================================${NC}"
echo ""
echo "Run the checker:"
echo "  cd src && python3 main.py"
echo ""
