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
    mv sing-box-${VERSION#v}-linux-amd64 sing-box
    chmod +x sing-box

    rm sing-box.tar.gz

    echo -e "${GREEN}sing-box installed successfully!${NC}"
else
    echo -e "${GREEN}sing-box already installed${NC}"
fi

echo -e "\n${GREEN}========================================="
echo "  Setup Complete!"
echo "=========================================${NC}"
echo ""
echo "Run the checker:"
echo "  cd src && python3 main.py"
echo ""
