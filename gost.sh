#!/bin/bash

# ==================================================
# Gost Manager - STABLE SILENT FIX (v9.3.4)
# Creator: UnknownZero (MOD by request)
# Focus:
#  - FIX CRASH: Removed invalid '-L warn' flag
#  - FIX LOG FLOOD: Set StandardError=null (Total Silence)
#  - GOGC=100 (High Performance)
# ==================================================

# --- Colors (Safe Palette) ---
NC='\033[0m'
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
HI_CYAN='\033[0;96m'
HI_PINK='\033[0;95m'
HI_GREEN='\033[0;92m'

# --- Icons ---
ICON_ROCKET="🚀"
ICON_LOCK="🔒"
ICON_LB="⚖️"
ICON_GEAR="🔧"
ICON_LOGS="📊"
ICON_TRASH="🗑️"
ICON_EXIT="🚪"
ICON_CPU="🧠"
ICON_RAM="💾"
ICON_NET="🌐"
ICON_INSTALL="💿"
ICON_RESTART="🔄"
ICON_DNS="🛡️"
ICON_PROXY="🔌"

# --- Paths ---
CONFIG_DIR="/etc/gost"
CONFIG_FILE="/etc/gost/config.yaml"
SERVICE_FILE="/etc/systemd/system/gost.service"
CERT_DIR="/etc/gost/certs"
YQ_BIN="/usr/bin/yq"

# --- Shortcut ---
SHORTCUT_BIN="/usr/local/bin/igost"
REPO_URL="https://raw.githubusercontent.com/Sir-Adnan/Gost-Manager/main/gost.sh"

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Please run as root.${NC}"
   exit 1
fi

# ==================================================
#  SMALL UTILS
# ==================================================

confirm_yes() {
    local ans="$1"
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

ask_input() { echo -ne "  ${HI_PINK}➤ $1 : ${NC}"; }
section_title() { echo -e "\n  ${BOLD}${HI_CYAN}:: $1 ::${NC}"; }
info_msg() { echo -e "  ${YELLOW}ℹ${NC} ${BLUE}$1${NC}"; }

normalize_ip() {
    local input_ip=$1
    if [[ "$input_ip" == *":"* ]]; then
        if [[ "$input_ip" == \[*\] ]]; then echo "$input_ip"; else echo "[$input_ip]"; fi
    else
        echo "$input_ip"
    fi
}

validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

backup_config() { cp "$CONFIG_FILE" "${CONFIG_FILE}.bak" 2>/dev/null; }

# ==================================================
#  VISUAL ENGINE
# ==================================================

draw_logo() {
    echo -e "${HI_CYAN}"
    echo "   ______  ____  _______ ______   "
    echo "  / ____/ / __ \/ ___/ //_  __/   "
    echo " / / __  / / / /\__ \/ / / /      "
    echo "/ /_/ / / /_/ /___/ / / / /       "
    echo "\____/  \____//____/ /_/ /_/      "
    echo "                                  "
    echo -e "    ${PURPLE}M  A  N  A  G  E  R    ${BOLD}v 9 . 3${NC}"
    echo -e "         ${HI_PINK}By UnknownZero${NC}"
    echo ""
}

draw_line() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_option() {
    local id="$1"
    local icon="$2"
    local title="$3"
    local desc="$4"
    local total_width=45
    local title_len=${#title}
    local dots_count=$((total_width - title_len))
    local dots=""
    for ((i=0; i<dots_count; i++)); do dots="${dots}."; done
    echo -e "  ${HI_CYAN}[${id}]${NC} ${icon} ${BOLD}${title}${NC} ${BLUE}${dots}${NC} ${YELLOW}${desc}${NC}"
}

show_guide() {
    local title="$1"
    local text="$2"
    echo ""
    echo -e "  ${HI_PINK}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}GUIDE:${NC} ${BOLD}$title${NC}"
    echo -e "  ${HI_PINK}╠══════════════════════════════════════════════════════════╝${NC}"
    echo -e "  ${HI_PINK}║${NC} $text"
    echo -e "  ${HI_PINK}╚══════════════════════════════════════════════════════════${NC}"
    echo ""
}

show_warning() {
    echo -e "  ${RED}⚠ WARNING:${NC} ${YELLOW}Use only A-Z, 0-9. NO special chars ( \" ' $ \\ )!${NC}"
}

# --------------------------------------------------
# Dashboard Caching
# --------------------------------------------------
CACHE_TTL=5
LAST_STATS_TS=0
C_SERVER_IP=""
C_RAM_USAGE=""
C_LOAD=""
C_TUNNELS="0"

refresh_stats_if_needed() {
    local now
    now=$(date +%s)
    if (( now - LAST_STATS_TS < CACHE_TTL )); then
        return 0
    fi
    LAST_STATS_TS=$now

    C_SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    C_RAM_USAGE=$(free -h 2>/dev/null | awk '/Mem:/ {print $3 "/" $2}')
    C_LOAD=$(awk '{print $1}' /proc/loadavg 2>/dev/null)

    if [ -f "$CONFIG_FILE" ]; then
        local t
        t=$($YQ_BIN '.services | length' "$CONFIG_FILE" 2>/dev/null)
        [[ -z "$t" ]] && t="0"
        C_TUNNELS="$t"
    else
        C_TUNNELS="0"
    fi
}

draw_dashboard() {
    clear
    draw_logo
    draw_line

    refresh_stats_if_needed

    local STATUS
    if systemctl is-active --quiet gost; then
        STATUS="${HI_GREEN}ACTIVE${NC}"
    else
        STATUS="${RED}OFFLINE${NC}"
    fi

    local DEBUG_MODE
    if grep -q "^StandardOutput=journal" "$SERVICE_FILE" 2>/dev/null; then
        DEBUG_MODE="${YELLOW}[DEBUG ON]${NC}"
    else
        DEBUG_MODE="${HI_GREEN}[SILENT]${NC}"
    fi

    echo -e "  ${ICON_NET} IP: ${BOLD}${C_SERVER_IP}${NC}"
    echo -e "  ${ICON_RAM} RAM: ${BOLD}${C_RAM_USAGE}${NC}   ${ICON_CPU} Load: ${BOLD}${C_LOAD}${NC}"
    echo -e "  ${ICON_GEAR} Status: ${STATUS}   ${ICON_LOGS} Mode: ${DEBUG_MODE}   ${ICON_ROCKET} Tunnels: ${HI_GREEN}${C_TUNNELS}${NC}"

    draw_line
    echo ""

    print_option "1" "$ICON_ROCKET" "Direct Tunnel" "Simple / mTCP"
    print_option "2" "$ICON_LOCK" "Secure Tunnel" "WSS/KCP/H2/SS"
    print_option "3" "$ICON_LB" "Load Balancer" "Multi-node Dist"
    print_option "4" "$ICON_PROXY" "Simple Proxy" "SOCKS5 / HTTP"
    print_option "5" "$ICON_DNS" "Secure DNS" "DoH / UDP"
    print_option "6" "$ICON_TRASH" "Delete Service" "Remove Active"
    print_option "7" "$ICON_GEAR" "Edit Config" "Manual (Nano)"
    print_option "8" "$ICON_LOGS" "Logs" "Disk & Debug"
    print_option "9" "$ICON_RESTART" "Auto-Restart" "Watchdog (Light)"
    print_option "10" "$ICON_TRASH" "Uninstall" "Remove All"
    print_option "0" "$ICON_EXIT" "Exit" "Close Script"

    echo ""
    draw_line
    printf "  ${HI_PINK}➤ Select Option : ${NC}"
}

# ==================================================
#  DEPENDENCIES
# ==================================================

install_dependencies() {
    local NEED_INSTALL=false
    if ! command -v curl &> /dev/null || ! command -v openssl &> /dev/null || ! command -v lsof &> /dev/null || ! command -v nc &> /dev/null; then
        NEED_INSTALL=true
    fi

    if [ "$NEED_INSTALL" = true ]; then
        echo -e "${BLUE}Installing core dependencies...${NC}"
        apt-get update -q && apt-get install -y curl openssl lsof nano netcat-openbsd vnstat -q logrotate
    fi

    if [ ! -f "$YQ_BIN" ]; then
        local ARCH YQ_URL
        ARCH=$(dpkg --print-architecture)
        if [[ "$ARCH" == "amd64" ]]; then
            YQ_URL="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64"
        elif [[ "$ARCH" == "arm64" ]]; then
            YQ_URL="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_arm64"
        else
            echo -e "${RED}Unsupported architecture for yq: ${ARCH}${NC}"
            exit 1
        fi
        curl -L -o "$YQ_BIN" "$YQ_URL" > /dev/null 2>&1
        chmod +x "$YQ_BIN"
    fi

    if ! command -v gost &> /dev/null; then
        bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install > /dev/null 2>&1
    fi

    mkdir -p "$CONFIG_DIR" "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    if [ ! -s "$CONFIG_FILE" ]; then echo "services: []" > "$CONFIG_FILE"; fi
}

setup_shortcut() {
    if [ ! -s "$SHORTCUT_BIN" ]; then
        echo ""
        draw_line
        echo -e "  ${ICON_INSTALL}  ${BOLD}Setup 'igost' Shortcut?${NC}"
        echo -e "  ${BLUE}Allows you to run the manager by typing 'igost'.${NC}"
        echo ""

        echo -ne "  ${HI_PINK}➤ Install (y/yes to confirm)? : ${NC}"
        read -r install_opt
        install_opt=${install_opt:-y}

        if confirm_yes "$install_opt"; then
            echo -e "  ${YELLOW}Downloading script to $SHORTCUT_BIN...${NC}"
            curl -L -o "$SHORTCUT_BIN" -fsSL "$REPO_URL"
            if [ -s "$SHORTCUT_BIN" ]; then
                chmod +x "$SHORTCUT_BIN"
                echo -e "  ${HI_GREEN}✔ Installed! Type 'igost' to run.${NC}"
                sleep 2
            else
                echo -e "  ${RED}✖ Download failed.${NC}"
                sleep 2
            fi
        fi
    fi
}

check_port_safety() {
    local port=$1
    if $YQ_BIN ".services[].addr" "$CONFIG_FILE" 2>/dev/null | grep -q ":$port"; then
        echo -e "  ${RED}✖ Port $port is already configured!${NC}"; return 1
    fi
    if lsof -i :"$port" > /dev/null 2>&1; then
        echo -e "  ${RED}✖ Port $port is busy in system!${NC}"; return 1
    fi
    return 0
}

check_name_safety() {
    local name=$1
    if $YQ_BIN ".services[].name" "$CONFIG_FILE" 2>/dev/null | tr -d '"' | grep -Fxq "$name"; then
        echo -e "  ${RED}✖ Name '$name' already exists!${NC}"; return 1
    fi
    return 0
}

apply_config() {
    echo -e "\n${BLUE}--- Reloading Service ---${NC}"
    systemctl restart gost
    sleep 1
    if systemctl is-active --quiet gost; then
        echo -e "  ${HI_GREEN}✔ Success! Service is running.${NC}"
        read -r -p "  Press Enter to continue..."
    else
        echo -e "  ${RED}✖ Failed! Restoring backup...${NC}"
        [ -f "${CONFIG_FILE}.bak" ] && mv "${CONFIG_FILE}.bak" "$CONFIG_FILE" && systemctl restart gost
        journalctl -u gost -n 5 --no-pager
        read -r -p "  Press Enter..."
    fi
    LAST_STATS_TS=0
}

# ==================================================
#  SYSTEMD SERVICE (v9.3.4 FIXED)
#   - Silent Output + Silent Error (Total Silence)
#   - GOGC=100
# ==================================================

create_service() {
    local GOST_BIN
    GOST_BIN=$(command -v gost)
    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Gost Service High Performance
After=network.target

[Service]
Type=simple
User=root
# Performance Tuning
Environment="GOGC=100"

# --- STANDARD EXECUTION (No args that cause crash) ---
ExecStart=$GOST_BIN -C $CONFIG_FILE

# --- TOTAL SILENCE (Fixes Log Flood) ---
# We discard both stdout and stderr to prevent disk filling
StandardOutput=null
StandardError=null

Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=512000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable gost >/dev/null 2>&1
}

# ==================================================
#  AUTO LOG OPTIMIZATION
# ==================================================

auto_clean_logs() {
    local MAX_USE="120M"
    local KEEP_FREE="200M"
    local MAX_FILE="20M"

    mkdir -p /etc/systemd/journald.conf.d
    cat <<EOF > /etc/systemd/journald.conf.d/99-gost-manager.conf
[Journal]
SystemMaxUse=$MAX_USE
SystemKeepFree=$KEEP_FREE
SystemMaxFileSize=$MAX_FILE
RateLimitIntervalSec=30s
RateLimitBurst=1000
EOF

    systemctl restart systemd-journald >/dev/null 2>&1
    journalctl --vacuum-size="$MAX_USE" >/dev/null 2>&1
}

# ==================================================
#  DEBUG TOGGLE
# ==================================================

toggle_debug_mode() {
    echo ""
    if grep -q "^StandardOutput=null" "$SERVICE_FILE" 2>/dev/null; then
        # Enable Debug (Full Logs)
        sed -i 's/^StandardOutput=null/StandardOutput=journal/' "$SERVICE_FILE"
        sed -i 's/^StandardError=null/StandardError=journal/' "$SERVICE_FILE"
        
        systemctl daemon-reload
        systemctl restart gost
        echo -e "  ${YELLOW}⚠ DEBUG MODE ENABLED.${NC} ${BLUE}Logs are now writing to disk.${NC}"
    else
        # Disable Debug (Total Silence)
        sed -i 's/^StandardOutput=journal/StandardOutput=null/' "$SERVICE_FILE"
        sed -i 's/^StandardError=journal/StandardError=null/' "$SERVICE_FILE"
        
        systemctl daemon-reload
        systemctl restart gost
        echo -e "  ${HI_GREEN}✔ SILENT MODE ENABLED.${NC} ${BLUE}All logs disabled.${NC}"
    fi
    sleep 2
}

# ==================================================
#  CORE FUNCTIONS
# ==================================================

add_tunnel() {
    draw_dashboard
    section_title "ADD DIRECT TUNNEL"
    show_guide "Direct Tunnel & mTCP" \
    "Use this for simple forwarding (Relay).\n  ${BOLD}[1-2] TCP/UDP:${NC} Standard forwarding.\n  ${BOLD}[3] mTCP:${NC} (Turbo) Sends multiple requests in one connection."

    show_warning
    echo ""
    ask_input "Service Name"; read -r s_name
    check_name_safety "$s_name" || { sleep 1; return; }

    ask_input "Local Port"; read -r lport
    validate_port "$lport" || { echo -e "  ${RED}Bad Port${NC}"; sleep 1; return; }
    check_port_safety "$lport" || { sleep 1; return; }

    echo ""
    ask_input "Dest IP"; read -r raw_ip
    dip=$(normalize_ip "$raw_ip")
    ask_input "Dest Port"; read -r dport
    validate_port "$dport" || { echo -e "  ${RED}Bad Dest Port${NC}"; sleep 1; return; }

    echo ""
    echo -e "  ${BOLD}Protocol Selection:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} TCP Only"
    echo -e "  ${HI_CYAN}[2]${NC} UDP Only"
    echo -e "  ${HI_CYAN}[3]${NC} mTCP ${HI_PINK}(Turbo Multiplex)${NC}"
    echo -e "  ${HI_CYAN}[4]${NC} Dual Stack ${HI_GREEN}(TCP+UDP)${NC}"
    echo ""
    ask_input "Select"; read -r proto

    backup_config
    node_tcp="{\"addr\": \"$dip:$dport\"}"
    node_udp="{\"addr\": \"$dip:$dport\"}"

    if [[ "$proto" == "3" ]]; then
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-mtcp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"tcp\"}, \"listener\": {\"type\": \"mtcp\"}, \"forwarder\": {\"nodes\": [$node_tcp]}}]" "$CONFIG_FILE"
    fi

    if [[ "$proto" == "1" || "$proto" == "4" ]]; then
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-tcp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"tcp\"}, \"listener\": {\"type\": \"tcp\"}, \"forwarder\": {\"nodes\": [$node_tcp]}}]" "$CONFIG_FILE"
    fi
    if [[ "$proto" == "2" || "$proto" == "4" ]]; then
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-udp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"udp\"}, \"listener\": {\"type\": \"udp\"}, \"forwarder\": {\"nodes\": [$node_udp]}}]" "$CONFIG_FILE"
    fi
    apply_config
}

add_secure() {
    draw_dashboard
    section_title "SECURE ENCRYPTED TUNNEL"
    show_guide "Secure Protocols" \
    "Choose protocol:\n  ${BOLD}mWSS:${NC} Turbo (Websocket+Mux).\n  ${BOLD}KCP:${NC} Anti-Packet Loss.\n  ${BOLD}Shadowsocks:${NC} With Cipher selection."

    echo -e "  ${HI_CYAN}[1]${NC} Sender / Client   ${BLUE}(Iran Server)${NC}"
    echo -e "  ${HI_CYAN}[2]${NC} Receiver / Server ${BLUE}(Foreign Server)${NC}"
    echo ""
    ask_input "Select Role"; read -r side

    if [[ "$side" == "1" ]]; then
        section_title "SENDER CONFIGURATION"
        show_warning
        echo ""
        ask_input "Service Name"; read -r s_name
        check_name_safety "$s_name" || { sleep 1; return; }
        ask_input "Local Port"; read -r lport
        validate_port "$lport" || { echo -e "  ${RED}Bad Port${NC}"; sleep 1; return; }
        check_port_safety "$lport" || { sleep 1; return; }

        echo ""
        ask_input "Remote IP"; read -r raw_rip
        rip=$(normalize_ip "$raw_rip")
        ask_input "Remote Port"; read -r rport
        validate_port "$rport" || { echo -e "  ${RED}Bad Remote Port${NC}"; sleep 1; return; }

        ask_input "SNI Domain (Optional)"; read -r sni
        [[ -z "$sni" ]] && sni="google.com"

        echo -e "\n  ${BOLD}Protocol:${NC}"
        echo -e "  ${HI_CYAN}[1]${NC} WSS"
        echo -e "  ${HI_CYAN}[2]${NC} mWSS ${HI_PINK}(Turbo)${NC}"
        echo -e "  ${HI_CYAN}[3]${NC} gRPC"
        echo -e "  ${HI_CYAN}[4]${NC} QUIC"
        echo -e "  ${HI_CYAN}[5]${NC} H2   ${HI_GREEN}(HTTP/2)${NC}"
        echo -e "  ${HI_CYAN}[6]${NC} KCP  ${YELLOW}(Anti-Loss)${NC}"
        echo -e "  ${HI_CYAN}[7]${NC} Shadowsocks"
        echo ""
        ask_input "Select"; read -r t_opt

        case $t_opt in
            2) tr="mwss";;
            3) tr="grpc";;
            4) tr="quic";;
            5) tr="h2";;
            6) tr="kcp";;
            7) tr="ss";;
            *) tr="wss";;
        esac

        extra_meta=""
        if [[ "$tr" == "ss" ]]; then
            echo -e "\n  ${BOLD}Cipher:${NC}"
            echo -e "  ${HI_CYAN}[1]${NC} AES-256-GCM"
            echo -e "  ${HI_CYAN}[2]${NC} Chacha20-IETF-Poly1305"
            echo -e "  ${HI_CYAN}[3]${NC} None"
            ask_input "Select"; read -r c_opt
            case $c_opt in
                2) cipher="chacha20-ietf-poly1305";;
                3) cipher="none";;
                *) cipher="aes-256-gcm";;
            esac

            ask_input "Password"; read -r ss_pass
            extra_meta=", \"metadata\": {\"method\": \"$cipher\", \"password\": \"$ss_pass\"}"
        fi

        backup_config

        if [[ "$tr" == "ss" ]]; then
            FWD_JSON="{\"nodes\": [{\"addr\": \"$rip:$rport\", \"connector\": {\"type\": \"shadowsocks\"$extra_meta}, \"dialer\": {\"type\": \"tcp\"}}]}"
        else
            FWD_JSON="{\"nodes\": [{\"addr\": \"$rip:$rport\", \"connector\": {\"type\": \"relay\"}, \"dialer\": {\"type\": \"$tr\", \"tls\": {\"secure\": false, \"serverName\": \"$sni\"}}}]}"
        fi

        $YQ_BIN -i ".services += [{\"name\": \"$s_name-dual\", \"addr\": \":$lport\", \"handler\": {\"type\": \"tcp\"}, \"listener\": {\"type\": \"tcp\"}, \"forwarder\": $FWD_JSON}]" "$CONFIG_FILE"
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-udp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"udp\"}, \"listener\": {\"type\": \"udp\"}, \"forwarder\": $FWD_JSON}]" "$CONFIG_FILE"

        apply_config

    elif [[ "$side" == "2" ]]; then
        section_title "RECEIVER CONFIGURATION"
        show_warning
        echo ""
        ask_input "Service Name"; read -r s_name
        check_name_safety "$s_name" || { sleep 1; return; }
        ask_input "Secure Port"; read -r lport
        validate_port "$lport" || { echo -e "  ${RED}Bad Port${NC}"; sleep 1; return; }
        check_port_safety "$lport" || { sleep 1; return; }

        echo -e "\n  ${BOLD}Protocol:${NC}"
        echo -e "  ${HI_CYAN}[1]${NC} WSS"
        echo -e "  ${HI_CYAN}[2]${NC} mWSS ${HI_PINK}(Turbo)${NC}"
        echo -e "  ${HI_CYAN}[3]${NC} gRPC"
        echo -e "  ${HI_CYAN}[4]${NC} QUIC"
        echo -e "  ${HI_CYAN}[5]${NC} H2"
        echo -e "  ${HI_CYAN}[6]${NC} KCP"
        echo -e "  ${HI_CYAN}[7]${NC} Shadowsocks"
        echo ""
        ask_input "Select"; read -r t_opt
        case $t_opt in
            2) tr="mwss";;
            3) tr="grpc";;
            4) tr="quic";;
            5) tr="h2";;
            6) tr="kcp";;
            7) tr="ss";;
            *) tr="wss";;
        esac

        if [[ "$tr" == "ss" ]]; then
            echo -e "\n  ${BOLD}Cipher:${NC}"
            echo -e "  ${HI_CYAN}[1]${NC} AES-256-GCM"
            echo -e "  ${HI_CYAN}[2]${NC} Chacha20-IETF-Poly1305"
            echo -e "  ${HI_CYAN}[3]${NC} None"
            ask_input "Select"; read -r c_opt
            case $c_opt in
                2) cipher="chacha20-ietf-poly1305";;
                3) cipher="none";;
                *) cipher="aes-256-gcm";;
            esac
            ask_input "Password"; read -r ss_pass
            tr="shadowsocks"
        else
            echo ""
            ask_input "Forward IP"; read -r raw_tip
            tip=$(normalize_ip "$raw_tip")
            ask_input "Forward Port"; read -r tport
            validate_port "$tport" || { echo -e "  ${RED}Bad Forward Port${NC}"; sleep 1; return; }

            ask_input "Cert Domain"; read -r cert_cn
            [[ -z "$cert_cn" ]] && cert_cn="update.microsoft.com"

            c_path="$CERT_DIR/cert_${lport}.pem"
            k_path="$CERT_DIR/key_${lport}.pem"
            echo -e "  ${BLUE}Generating Certificates...${NC}"
            openssl req -newkey rsa:2048 -nodes -keyout "$k_path" -x509 -days 3650 -out "$c_path" -subj "/CN=$cert_cn" > /dev/null 2>&1
            chmod 600 "$k_path"
        fi

        backup_config

        if [[ "$tr" == "shadowsocks" ]]; then
            ask_input "Forward IP"; read -r raw_tip
            tip=$(normalize_ip "$raw_tip")
            ask_input "Forward Port"; read -r tport
            validate_port "$tport" || { echo -e "  ${RED}Bad Forward Port${NC}"; sleep 1; return; }

            s_name="$s_name" lport=":$lport" taddr="$tip:$tport" pass="$ss_pass" cipher="$cipher" \
            $YQ_BIN -i '.services += [{"name": env(s_name), "addr": env(lport), "handler": {"type": "shadowsocks", "metadata": {"password": env(pass), "method": env(cipher)}}, "listener": {"type": "tcp"}, "forwarder": {"nodes": [{"addr": env(taddr)}]}}]' "$CONFIG_FILE"
        else
            s_name="$s_name" lport=":$lport" tr="$tr" taddr="$tip:$tport" cert="$c_path" key="$k_path" \
            $YQ_BIN -i '.services += [{"name": env(s_name), "addr": env(lport), "handler": {"type": "relay"}, "listener": {"type": env(tr), "tls": {"certFile": env(cert), "keyFile": env(key)}}, "forwarder": {"nodes": [{"addr": env(taddr)}]}}]' "$CONFIG_FILE"
        fi
        apply_config
    fi
}

add_lb() {
    draw_dashboard
    section_title "ADD LOAD BALANCER"
    info_msg "Distribute traffic between multiple servers."
    echo ""
    ask_input "Service Name"; read -r s_name
    check_name_safety "$s_name" || { sleep 1; return; }
    ask_input "Local Port"; read -r lport
    validate_port "$lport" || { echo -e "  ${RED}Bad Port${NC}"; sleep 1; return; }
    check_port_safety "$lport" || { sleep 1; return; }

    echo -e "\n  ${BOLD}Strategy:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} Round Robin   ${BLUE}Rotate IPs${NC}"
    echo -e "  ${HI_CYAN}[2]${NC} Random        ${BLUE}Random pick${NC}"
    echo -e "  ${HI_CYAN}[3]${NC} Least Conn    ${BLUE}Smart load${NC}"
    echo -e "  ${HI_CYAN}[4]${NC} Hashing       ${BLUE}Sticky IP${NC}"
    echo ""
    ask_input "Select"; read -r s_opt
    case $s_opt in 2) strat="random";; 3) strat="least";; 4) strat="hashing";; *) strat="round";; esac

    echo -e "\n  ${BOLD}Protocol:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} TCP Only"
    echo -e "  ${HI_CYAN}[2]${NC} UDP Only"
    echo -e "  ${HI_CYAN}[3]${NC} Dual Stack"
    echo ""
    ask_input "Select"; read -r proto

    declare -a NODES
    section_title "Manage Nodes"
    info_msg "Leave IP empty and press ENTER to finish."
    while true; do
        echo ""
        ask_input "Node IP"; read -r raw_nip
        [[ -z "$raw_nip" ]] && break
        nip=$(normalize_ip "$raw_nip")
        ask_input "Node Port"; read -r nport
        validate_port "$nport" || { echo -e "  ${RED}Bad Node Port${NC}"; continue; }
        NODES+=("{\"addr\": \"$nip:$nport\"}")
        echo -e "    ${HI_GREEN}✔ Added${NC}"
    done

    if [ ${#NODES[@]} -eq 0 ]; then echo -e "  ${RED}No nodes!${NC}"; sleep 1; return; fi
    NODES_STR=$(IFS=, ; echo "${NODES[*]}")

    backup_config
    if [[ "$proto" == "1" || "$proto" == "3" ]]; then
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-tcp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"tcp\"}, \"listener\": {\"type\": \"tcp\"}, \"forwarder\": {\"selector\": {\"strategy\": \"$strat\", \"maxFails\": 3, \"failTimeout\": \"30s\"}, \"nodes\": [$NODES_STR]}}]" "$CONFIG_FILE"
    fi
    if [[ "$proto" == "2" || "$proto" == "3" ]]; then
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-udp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"udp\"}, \"listener\": {\"type\": \"udp\"}, \"forwarder\": {\"selector\": {\"strategy\": \"$strat\", \"maxFails\": 3, \"failTimeout\": \"30s\"}, \"nodes\": [$NODES_STR]}}]" "$CONFIG_FILE"
    fi
    apply_config
}

add_simple_proxy() {
    draw_dashboard
    section_title "SIMPLE PROXY SERVER"
    show_guide "Proxy Mode" \
    "Turns this server into a direct proxy.\n  ${BOLD}SOCKS5 / HTTP:${NC} Use these in Telegram, Browser, or Apps.\n  ${BOLD}Auth:${NC} Set Username/Password for security."

    show_warning
    echo ""
    ask_input "Service Name"; read -r s_name
    check_name_safety "$s_name" || { sleep 1; return; }
    ask_input "Port"; read -r lport
    validate_port "$lport" || { echo -e "  ${RED}Bad Port${NC}"; sleep 1; return; }
    check_port_safety "$lport" || { sleep 1; return; }

    echo -e "\n  ${BOLD}Type:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} SOCKS5"
    echo -e "  ${HI_CYAN}[2]${NC} HTTP"
    ask_input "Select"; read -r p_opt

    ask_input "Username (Leave empty for none)"; read -r p_user
    if [[ -n "$p_user" ]]; then
        ask_input "Password"; read -r p_pass
    fi

    backup_config
    if [[ "$p_opt" == "2" ]]; then handler="http"; else handler="socks5"; fi

    s_name="$s_name" lport=":$lport" handler="$handler" p_user="$p_user" p_pass="$p_pass"

    if [[ -n "$p_user" ]]; then
         $YQ_BIN -i '.services += [{"name": env(s_name), "addr": env(lport), "handler": {"type": env(handler), "auth": {"username": env(p_user), "password": env(p_pass)}}, "listener": {"type": "tcp"}}]' "$CONFIG_FILE"
    else
         $YQ_BIN -i '.services += [{"name": env(s_name), "addr": env(lport), "handler": {"type": env(handler)}, "listener": {"type": "tcp"}}]' "$CONFIG_FILE"
    fi
    apply_config
}

setup_dns() {
    draw_dashboard
    section_title "SECURE DNS SERVER"
    show_guide "Secure DNS (DoH)" \
    "Sets up a DNS resolver on your server.\n  ${BOLD}Prevent Leaks:${NC} Forwards DNS queries securely.\n  ${BOLD}Protocol:${NC} Listens on UDP 53 (or custom port)."

    ask_input "Service Name"; read -r s_name
    check_name_safety "$s_name" || { sleep 1; return; }
    ask_input "Local Port (Default 53)"; read -r lport
    [[ -z "$lport" ]] && lport="53"
    validate_port "$lport" || { echo -e "  ${RED}Bad Port${NC}"; sleep 1; return; }
    check_port_safety "$lport" || { sleep 1; return; }

    echo -e "\n  ${BOLD}Upstream Provider:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} Cloudflare (1.1.1.1)"
    echo -e "  ${HI_CYAN}[2]${NC} Google (8.8.8.8)"
    echo -e "  ${HI_CYAN}[3]${NC} Custom"
    ask_input "Select"; read -r d_opt

    case $d_opt in
        1) up_dns="1.1.1.1";;
        2) up_dns="8.8.8.8";;
        *) ask_input "Enter DNS IP"; read -r up_dns;;
    esac

    backup_config
    $YQ_BIN -i ".services += [{\"name\": \"$s_name\", \"addr\": \":$lport\", \"handler\": {\"type\": \"dns\"}, \"listener\": {\"type\": \"udp\"}, \"forwarder\": {\"nodes\": [{\"addr\": \"$up_dns:53\"}]}}]" "$CONFIG_FILE"
    apply_config
}

delete_service() {
    draw_dashboard
    section_title "DELETE SERVICE"
    local count
    count=$($YQ_BIN '.services | length' "$CONFIG_FILE" 2>/dev/null)
    [[ -z "$count" ]] && count=0
    if [[ "$count" == "0" ]]; then echo -e "  ${YELLOW}No services configured.${NC}"; sleep 1; return; fi

    printf "  ${BLUE}%-4s %-25s %-15s${NC}\n" "ID" "NAME" "PORT"
    echo -e "  ${BLUE}────────────────────────────────────────────${NC}"
    for ((i=0; i<count; i++)); do
        s_name=$($YQ_BIN ".services[$i].name" "$CONFIG_FILE" 2>/dev/null | tr -d '"')
        s_port=$($YQ_BIN ".services[$i].addr" "$CONFIG_FILE" 2>/dev/null | tr -d '"')
        printf "  ${HI_CYAN}[%d]${NC}  ${BOLD}%-25s${NC} %-15s\n" "$i" "$s_name" "$s_port"
    done
    echo ""
    ask_input "Enter ID (c to cancel)"; read -r del_id
    [[ "$del_id" == "c" || "$del_id" == "C" ]] && return
    if [[ "$del_id" =~ ^[0-9]+$ ]] && [ "$del_id" -lt "$count" ]; then
        backup_config
        $YQ_BIN -i "del(.services[$del_id])" "$CONFIG_FILE"
        apply_config
    fi
}

# ==================================================
#  LIGHTWEIGHT WATCHDOG (no top/bc)
#   - Uses /proc/loadavg (very low CPU)
# ==================================================

setup_watchdog() {
    draw_dashboard
    section_title "LIGHT WATCHDOG (LOAD AVG)"
    info_msg "Restarts Gost if 1-min load average stays too high. Very low CPU overhead."
    echo ""

    local cores
    cores=$(nproc 2>/dev/null)
    [[ -z "$cores" || "$cores" -le 0 ]] && cores=1
    local default_threshold=$((cores * 2))

    echo -e "  ${YELLOW}Default threshold = cores*2 => ${default_threshold}${NC}"
    ask_input "Enable Watchdog? (y/yes)"; read -r confirm
    confirm=${confirm:-y}
    if ! confirm_yes "$confirm"; then return; fi

    ask_input "Load threshold (ENTER for ${default_threshold})"; read -r thr
    [[ -z "$thr" ]] && thr="$default_threshold"
    [[ ! "$thr" =~ ^[0-9]+$ ]] && thr="$default_threshold"

    cat <<'EOF' > /usr/local/bin/gost_watchdog.sh
#!/bin/bash
# Lightweight watchdog based on /proc/loadavg (1-min avg)
THRESHOLD_FILE="/etc/gost/watchdog_threshold"
LOG="/var/log/gost_watchdog.log"

thr=0
if [ -f "$THRESHOLD_FILE" ]; then
  thr=$(cat "$THRESHOLD_FILE" 2>/dev/null | tr -dc '0-9')
fi
[ -z "$thr" ] && thr=4

load1=$(awk '{print int($1)}' /proc/loadavg 2>/dev/null)
[ -z "$load1" ] && load1=0

if [ "$load1" -ge "$thr" ]; then
  systemctl restart gost
  echo "$(date): Load Critical (${load1} >= ${thr}). Gost restarted." >> "$LOG"
fi
EOF
    chmod +x /usr/local/bin/gost_watchdog.sh

    mkdir -p /etc/gost
    echo "$thr" > /etc/gost/watchdog_threshold

    # Install cron entry (dedupe)
    (crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/gost_watchdog.sh") | sort -u | crontab -

    echo -e "\n  ${HI_GREEN}✔ Watchdog Activated.${NC} Threshold=${thr} (1-min load)"
    sleep 2
}

menu_uninstall() {
    draw_dashboard
    section_title "UNINSTALL MANAGER"
    echo -e "  ${RED}⚠ WARNING: This will remove Gost, configs, yq, watchdog, and shortcut!${NC}"
    echo ""
    ask_input "Confirm (y/yes)"; read -r c
    if confirm_yes "$c"; then
        systemctl stop gost >/dev/null 2>&1
        systemctl disable gost >/dev/null 2>&1
        rm -f /usr/local/bin/gost_watchdog.sh
        crontab -l 2>/dev/null | grep -v "gost_watchdog.sh" | crontab - 2>/dev/null
        rm -rf "$CONFIG_DIR" "$SERVICE_FILE" "$YQ_BIN" "$SHORTCUT_BIN"
        systemctl daemon-reload
        rm -f "$(command -v gost)" 2>/dev/null
        echo -e "\n  ${HI_GREEN}✔ Uninstalled successfully.${NC}"
        exit 0
    fi
}

menu_exit() {
    clear
    echo -e "\n  ${HI_PINK}Goodbye! 👋${NC}"
    exit 0
}

# ==================================================
#  LOGS MENU
#   - Syslog truncate ONLY here (with confirmation)
# ==================================================

logs_menu() {
    while true; do
        draw_dashboard
        section_title "LOGS & DISK CONTROL"
        info_msg "Tiny disk mode: journald is limited + you can toggle debug."
        echo ""
        # --- FIXED GUIDE SECTION START ---
        echo -e "  ${HI_PINK}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}GUIDE:${NC} ${BOLD}Logs Menu Options${NC}"
        echo -e "  ${HI_PINK}╠══════════════════════════════════════════════════════════╝${NC}"
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}[1] Live Logs:${NC} Watch logs in real-time (Ctrl+C to exit)."
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}[2] Disk Usage:${NC} Show how much space logs are taking."
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}[3] Vacuum Size:${NC} Reduce logs to specific size (e.g. 100M)."
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}[4] Vacuum Time:${NC} Delete logs older than X (e.g. 7d)."
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}[5] Set Limits:${NC} Set permanent log size limits (Prevent full disk)."
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}[7] Clear Syslog:${NC} Danger! Deletes all system logs."
        echo -e "  ${HI_PINK}║${NC} ${HI_CYAN}[9] Debug Mode:${NC} Toggle between Silent (Errors only) & Full logs."
        echo -e "  ${HI_PINK}╚══════════════════════════════════════════════════════════${NC}"
        echo ""
        # --- FIXED GUIDE SECTION END ---

        echo -e "  ${HI_CYAN}[1]${NC} Follow Gost Logs (Live)"
        echo -e "  ${HI_CYAN}[2]${NC} Journal Disk Usage"
        echo -e "  ${HI_CYAN}[3]${NC} Vacuum Journal by Size"
        echo -e "  ${HI_CYAN}[4]${NC} Vacuum Journal by Time"
        echo -e "  ${HI_CYAN}[5]${NC} Set Journald Limits (Persistent)"
        echo -e "  ${HI_CYAN}[6]${NC} Force Logrotate (syslog)"
        echo -e "  ${HI_CYAN}[7]${NC} Truncate /var/log/syslog (Manual)"
        echo -e "  ${HI_CYAN}[8]${NC} Check Service Status"
        echo -e "  ${HI_CYAN}[9]${NC} Toggle Debug Mode (ON/OFF)"
        echo -e "  ${HI_CYAN}[0]${NC} Back"
        echo ""
        draw_line
        ask_input "Select"; read -r lopt

        case $lopt in
            1)
                clear
                echo -e "${BLUE}--- Following gost logs (Ctrl+C to stop) ---${NC}"
                journalctl -u gost -f
                ;;
            2)
                echo ""
                journalctl --disk-usage
                echo ""
                read -r -p "  Press Enter to continue..."
                ;;
            3)
                echo ""
                ask_input "Vacuum Size (e.g. 200M)"; read -r vsize
                [[ -z "$vsize" ]] && vsize="200M"
                echo -e "${BLUE}--- Vacuuming journal to size: $vsize ---${NC}"
                journalctl --vacuum-size="$vsize"
                echo ""
                journalctl --disk-usage
                echo ""
                read -r -p "  Press Enter to continue..."
                ;;
            4)
                echo ""
                ask_input "Vacuum Time (e.g. 7d)"; read -r vtime
                [[ -z "$vtime" ]] && vtime="7d"
                echo -e "${BLUE}--- Vacuuming journal older than: $vtime ---${NC}"
                journalctl --vacuum-time="$vtime"
                echo ""
                journalctl --disk-usage
                echo ""
                read -r -p "  Press Enter to continue..."
                ;;
            5)
                echo ""
                section_title "JOURNALD LIMITS"
                info_msg "Writes: /etc/systemd/journald.conf.d/99-gost-manager.conf"
                ask_input "SystemMaxUse (Default 120M)"; read -r jmax
                [[ -z "$jmax" ]] && jmax="120M"
                ask_input "SystemKeepFree (Default 200M)"; read -r jfree
                [[ -z "$jfree" ]] && jfree="200M"
                ask_input "SystemMaxFileSize (Default 20M)"; read -r jfile
                [[ -z "$jfile" ]] && jfile="20M"

                mkdir -p /etc/systemd/journald.conf.d
                cat <<EOF > /etc/systemd/journald.conf.d/99-gost-manager.conf
[Journal]
SystemMaxUse=$jmax
SystemKeepFree=$jfree
SystemMaxFileSize=$jfile
RateLimitIntervalSec=30s
RateLimitBurst=1000
EOF
                systemctl restart systemd-journald >/dev/null 2>&1
                journalctl --vacuum-size="$jmax" >/dev/null 2>&1
                echo ""
                echo -e "  ${HI_GREEN}✔ Journald limits applied.${NC}"
                journalctl --disk-usage
                echo ""
                read -r -p "  Press Enter to continue..."
                ;;
            6)
                echo ""
                if ! command -v logrotate &> /dev/null; then
                    echo -e "  ${RED}✖ logrotate not installed.${NC}"
                    read -r -p "  Press Enter..."
                else
                    echo -e "${BLUE}--- Running logrotate (forced) ---${NC}"
                    logrotate -f /etc/logrotate.conf
                    echo ""
                    du -sh /var/log/syslog* 2>/dev/null | sort -h
                    echo ""
                    read -r -p "  Press Enter to continue..."
                fi
                ;;
            7)
                echo ""
                echo -e "  ${RED}⚠ WARNING:${NC} ${YELLOW}This will EMPTY /var/log/syslog now.${NC}"
                ask_input "Confirm (y/yes)"; read -r c
                if confirm_yes "$c"; then
                    truncate -s 0 /var/log/syslog 2>/dev/null
                    echo -e "  ${HI_GREEN}✔ syslog truncated.${NC}"
                else
                    echo -e "  ${YELLOW}Canceled.${NC}"
                fi
                echo ""
                read -r -p "  Press Enter to continue..."
                ;;
            8)
                echo ""
                systemctl status gost --no-pager
                echo ""
                read -r -p "  Press Enter to continue..."
                ;;
            9)
                toggle_debug_mode
                ;;
            0)
                return
                ;;
            *)
                sleep 0.3
                ;;
        esac
    done
}

# ==================================================
#  MAIN LOOP
# ==================================================

install_dependencies
create_service
auto_clean_logs   # MUST run at startup (journald limit + vacuum)
setup_shortcut

while true; do
    draw_dashboard
    read -r opt
    case $opt in
        1) add_tunnel ;;
        2) add_secure ;;
        3) add_lb ;;
        4) add_simple_proxy ;;
        5) setup_dns ;;
        6) delete_service ;;
        7) backup_config; nano "$CONFIG_FILE"; apply_config ;;
        8) logs_menu ;;
        9) setup_watchdog ;;
        10) menu_uninstall ;;
        0) menu_exit ;;
        *) sleep 0.3 ;;
    esac
done
