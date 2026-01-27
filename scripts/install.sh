#!/bin/bash
#
# SingBox Manager - One-Click Installation Script
# Supports: install, uninstall, update, status
#
set -e

# ==================== Configuration ====================
VERSION="1.0.0"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/singbox-client"
SERVICE_NAME="singbox-client"
WEB_PORT=3333
REPO_URL="https://github.com/xiaokun/singbox-client"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==================== Helper Functions ====================
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root (sudo $0)"
        exit 1
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  SINGBOX_ARCH="amd64" ;;
        aarch64) SINGBOX_ARCH="arm64" ;;
        armv7l)  SINGBOX_ARCH="armv7" ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_info "Architecture: $SINGBOX_ARCH"
}

check_command() {
    command -v "$1" &> /dev/null
}

# ==================== sing-box Installation ====================
get_singbox_latest_version() {
    curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | \
        grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/'
}

install_singbox() {
    log_step "Installing sing-box..."

    local version
    version=$(get_singbox_latest_version)

    if [ -z "$version" ]; then
        log_error "Failed to get sing-box version"
        return 1
    fi

    log_info "sing-box version: $version"

    local url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${SINGBOX_ARCH}.tar.gz"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    log_info "Downloading sing-box..."
    if ! curl -L -o "$tmp_dir/sing-box.tar.gz" "$url" 2>/dev/null; then
        rm -rf "$tmp_dir"
        log_error "Download failed"
        return 1
    fi

    tar -xzf "$tmp_dir/sing-box.tar.gz" -C "$tmp_dir"
    cp "$tmp_dir/sing-box-${version}-linux-${SINGBOX_ARCH}/sing-box" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sing-box"

    # Set capabilities for TUN
    setcap cap_net_admin,cap_net_bind_service=+ep "$INSTALL_DIR/sing-box" 2>/dev/null || true

    rm -rf "$tmp_dir"
    log_info "sing-box installed: $version"
}

# ==================== singbox-client Installation ====================
build_client() {
    log_step "Building singbox-client..."

    if ! check_command go; then
        log_error "Go is not installed. Please install Go 1.21+"
        log_info "Install with: sudo apt install golang-go"
        exit 1
    fi

    local project_dir
    project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    cd "$project_dir"

    export GOPROXY=https://goproxy.cn,direct
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "$INSTALL_DIR/singbox-client" .
    chmod +x "$INSTALL_DIR/singbox-client"

    log_info "singbox-client built successfully"
}

create_service() {
    log_step "Creating systemd service..."

    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SingBox Client Manager
Documentation=https://github.com/xiaokun/singbox-client
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=SINGBOX_DATA_DIR=${DATA_DIR}
ExecStart=${INSTALL_DIR}/singbox-client
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Service created: ${SERVICE_NAME}"
}

create_directories() {
    log_step "Creating directories..."
    mkdir -p "$DATA_DIR"/{subscriptions,singbox}
    log_info "Data directory: $DATA_DIR"
}

# ==================== Main Commands ====================
do_install() {
    echo ""
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  SingBox Manager Installation  ${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""

    check_root
    detect_arch

    # Install sing-box
    if check_command sing-box; then
        local current_ver
        current_ver=$(sing-box version 2>/dev/null | head -n1 | awk '{print $3}')
        log_info "sing-box already installed: $current_ver"

        read -p "Update sing-box to latest? [y/N] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && install_singbox
    else
        install_singbox
    fi

    # Build client
    build_client

    # Setup
    create_directories
    create_service

    # Start service
    read -p "Start service now? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        systemctl enable ${SERVICE_NAME}
        systemctl start ${SERVICE_NAME}
        sleep 2

        if systemctl is-active --quiet ${SERVICE_NAME}; then
            log_info "Service started successfully"
        else
            log_warn "Service may not have started correctly"
            log_info "Check logs: journalctl -u ${SERVICE_NAME} -n 50"
        fi
    fi

    echo ""
    echo -e "${GREEN}========== Installation Complete ==========${NC}"
    echo ""
    echo "  Web Interface:  http://localhost:${WEB_PORT}"
    echo "  Data Directory: ${DATA_DIR}"
    echo ""
    echo "  Commands:"
    echo "    Start:   sudo systemctl start ${SERVICE_NAME}"
    echo "    Stop:    sudo systemctl stop ${SERVICE_NAME}"
    echo "    Status:  sudo systemctl status ${SERVICE_NAME}"
    echo "    Logs:    sudo journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo "  Quick Start:"
    echo "    1. Open http://localhost:${WEB_PORT}"
    echo "    2. Add subscription URL"
    echo "    3. Click Start to connect"
    echo ""
}

do_uninstall() {
    echo ""
    echo -e "${YELLOW}================================${NC}"
    echo -e "${YELLOW}  SingBox Manager Uninstall     ${NC}"
    echo -e "${YELLOW}================================${NC}"
    echo ""

    check_root

    read -p "Remove singbox-client completely? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cancelled"
        exit 0
    fi

    log_step "Stopping services..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true

    log_step "Removing files..."
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    rm -f "$INSTALL_DIR/singbox-client"

    systemctl daemon-reload

    read -p "Remove data directory ($DATA_DIR)? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        log_info "Data directory removed"
    fi

    read -p "Remove sing-box? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$INSTALL_DIR/sing-box"
        log_info "sing-box removed"
    fi

    log_info "Uninstall complete"
}

do_update() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  SingBox Manager Update        ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""

    check_root
    detect_arch

    # Update sing-box
    read -p "Update sing-box? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        install_singbox
    fi

    # Rebuild client
    log_step "Rebuilding singbox-client..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    build_client
    systemctl start ${SERVICE_NAME}

    log_info "Update complete"
}

do_status() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  SingBox Manager Status        ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""

    # Check singbox-client
    if check_command singbox-client; then
        echo -e "singbox-client: ${GREEN}installed${NC}"
    else
        echo -e "singbox-client: ${RED}not installed${NC}"
    fi

    # Check sing-box
    if check_command sing-box; then
        local ver
        ver=$(sing-box version 2>/dev/null | head -n1)
        echo -e "sing-box: ${GREEN}$ver${NC}"
    else
        echo -e "sing-box: ${RED}not installed${NC}"
    fi

    # Check service
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        echo -e "Service: ${GREEN}running${NC}"
    else
        echo -e "Service: ${RED}stopped${NC}"
    fi

    # Check API
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${WEB_PORT}/api/status" 2>/dev/null | grep -q "200"; then
        echo -e "API: ${GREEN}responding${NC}"

        # Get status
        local status
        status=$(curl -s "http://127.0.0.1:${WEB_PORT}/api/status" 2>/dev/null)
        if [ -n "$status" ]; then
            echo ""
            echo "Proxy Status:"
            echo "$status" | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; print(f\"  State: {d.get('state','unknown')}\"); print(f\"  Nodes: {d.get('node_count',0)}\"); print(f\"  Mode: {d.get('proxy_mode','unknown')}\"); print(f\"  Selected: {d.get('selected_node','none')}\")" 2>/dev/null || true
        fi
    else
        echo -e "API: ${RED}not responding${NC}"
    fi

    echo ""
}

show_help() {
    echo "SingBox Manager - Installation Script v${VERSION}"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install    Install singbox-client and sing-box"
    echo "  uninstall  Remove singbox-client"
    echo "  update     Update sing-box and rebuild client"
    echo "  status     Show current status"
    echo "  help       Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0 install    # Fresh installation"
    echo "  sudo $0 update     # Update to latest"
    echo "  sudo $0 status     # Check status"
    echo ""
}

# ==================== Main ====================
case "${1:-install}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    update)    do_update ;;
    status)    do_status ;;
    help|--help|-h) show_help ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
