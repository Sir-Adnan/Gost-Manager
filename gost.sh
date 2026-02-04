#!/bin/bash

# ==================================================
# Gost Manager - ADAPTIVE EDITION (v7.0)
# Creator: UnknownZero
# Focus: High Contrast, Light/Dark Theme Safe
# ==================================================

# --- Colors (Safe Palette) ---
# NC (No Color) allows the terminal to choose Black or White based on theme
NC='\033[0m'
BOLD='\033[1m'

# ANSI Colors (Adaptive) - These shift slightly based on terminal theme
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'

# High Intensity Colors (For Accents)
HI_CYAN='\033[0;96m'
HI_PINK='\033[0;95m'
HI_GREEN='\033[0;92m'
HI_YELLOW='\033[0;93m'

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

# --- Paths ---
CONFIG_DIR="/etc/gost"
CONFIG_FILE="/etc/gost/config.yaml"
SERVICE_FILE="/etc/systemd/system/gost.service"
CERT_DIR="/etc/gost/certs"
YQ_BIN="/usr/bin/yq"

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Please run as root.${NC}"
   exit 1
fi

# ==================================================
#  VISUAL ENGINE (Adaptive)
# ==================================================

draw_logo() {
    # Using Cyan for logo as it reads well on both black and white backgrounds
    echo -e "${HI_CYAN}"
    echo "   ______  ____  _______ ______   "
    echo "  / ____/ / __ \/ ___/ //_  __/   "
    echo " / / __  / / / /\__ \/ / / /      "
    echo "/ /_/ / / /_/ /___/ / / / /       "
    echo "\____/  \____//____/ /_/ /_/      "
    echo "                                  "
    echo -e "    ${PURPLE}M  A  N  A  G  E  R    ${BOLD}v 7 . 0${NC}"
    echo -e "         ${HI_PINK}By UnknownZero${NC}"
    echo ""
}

draw_line() {
    # Using Blue instead of Grey for better visibility on light themes
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Usage: print_option "ID" "Icon" "Title" "Description"
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
    
    # Structure: 
    # ID: Cyan (Readable on both)
    # Title: BOLD (Adapts to Black/White)
    # Dots: Blue (Subtle but visible)
    # Desc: Yellow (Darker yellow on light themes usually)
    echo -e "  ${HI_CYAN}[${id}]${NC} ${icon} ${BOLD}${title}${NC} ${BLUE}${dots}${NC} ${YELLOW}${desc}${NC}"
}

draw_dashboard() {
    clear
    draw_logo
    draw_line
    
    # System Stats
    SERVER_IP=$(hostname -I | awk '{print $1}')
    RAM_USAGE=$(free -h | awk '/Mem:/ {print $3 "/" $2}')
    LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1 | tr -d ' ')
    
    if [ -f "$CONFIG_FILE" ]; then
        TUNNELS=$($YQ_BIN '.services | length' "$CONFIG_FILE" 2>/dev/null)
    else
        TUNNELS=0
    fi
    [[ -z "$TUNNELS" ]] && TUNNELS=0

    if systemctl is-active --quiet gost; then
        STATUS="${HI_GREEN}ACTIVE${NC}"
    else
        STATUS="${RED}OFFLINE${NC}"
    fi

    # Dashboard Grid - Using BOLD for values to ensure contrast
    echo -e "  ${ICON_NET} IP: ${BOLD}${SERVER_IP}${NC}"
    echo -e "  ${ICON_RAM} RAM: ${BOLD}${RAM_USAGE}${NC}   ${ICON_CPU} Load: ${BOLD}${LOAD}${NC}"
    echo -e "  ${ICON_GEAR} Status: ${STATUS}   ${ICON_ROCKET} Tunnels: ${HI_GREEN}${TUNNELS}${NC}"
    
    draw_line
    echo ""
    
    # Menu Options
    print_option "1" "$ICON_ROCKET" "Direct Tunnel" "Simple Relay"
    print_option "2" "$ICON_LOCK" "Secure Tunnel" "TLS / WSS / gRPC"
    print_option "3" "$ICON_LB" "Load Balancer" "Multi-node Dist"
    print_option "4" "$ICON_TRASH" "Delete Service" "Remove Active"
    print_option "5" "$ICON_GEAR" "Edit Config" "Manual (Nano)"
    print_option "6" "$ICON_LOGS" "View Logs" "Live Monitor"
    print_option "7" "$ICON_EXIT" "Uninstall" "Remove All"
    print_option "0" "🔙" "Exit" "Close Script"
    
    echo ""
    draw_line
    printf "  ${HI_PINK}➤ Select Option : ${NC}"
}

# ==================================================
#  HELPER FUNCTIONS
# ==================================================

install_dependencies() {
    local NEED_INSTALL=false
    if ! command -v curl &> /dev/null || ! command -v openssl &> /dev/null || ! command -v lsof &> /dev/null || ! command -v nc &> /dev/null; then
        NEED_INSTALL=true
    fi

    if [ "$NEED_INSTALL" = true ]; then
        echo -e "${BLUE}Installing core dependencies...${NC}"
        apt-get update -q && apt-get install -y curl openssl lsof nano netcat-openbsd vnstat -q
    fi

    if [ ! -f "$YQ_BIN" ]; then
        ARCH=$(dpkg --print-architecture)
        if [[ "$ARCH" == "amd64" ]]; then YQ_URL="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64"; 
        elif [[ "$ARCH" == "arm64" ]]; then YQ_URL="https://github.com/mikefarah/yq/releases/latest/download/yq_linux_arm64"; fi
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

normalize_ip() {
    local input_ip=$1
    if [[ "$input_ip" == *":"* ]]; then
        if [[ "$input_ip" == \[*\] ]]; then echo "$input_ip"; else echo "[$input_ip]"; fi
    else
        echo "$input_ip"
    fi
}

validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

check_port_safety() {
    local port=$1
    if $YQ_BIN ".services[].addr" "$CONFIG_FILE" 2>/dev/null | grep -q ":$port"; then
        echo -e "  ${RED}✖ Port $port is already configured!${NC}"; return 1
    fi
    if lsof -i :$port > /dev/null; then
        echo -e "  ${RED}✖ Port $port is busy in system!${NC}"; return 1
    fi
    return 0
}

check_name_safety() {
    local name=$1
    if $YQ_BIN ".services[].name" "$CONFIG_FILE" 2>/dev/null | grep -q "^$name$"; then
        echo -e "  ${RED}✖ Name '$name' already exists!${NC}"; return 1
    fi
    return 0
}

backup_config() { cp "$CONFIG_FILE" "${CONFIG_FILE}.bak" 2>/dev/null; }

apply_config() {
    echo -e "\n${BLUE}--- Reloading Service ---${NC}"
    systemctl restart gost
    sleep 1
    if systemctl is-active --quiet gost; then
        echo -e "  ${HI_GREEN}✔ Success! Service is running.${NC}"
        read -p "  Press Enter to continue..."
    else
        echo -e "  ${RED}✖ Failed! Restoring backup...${NC}"
        [ -f "${CONFIG_FILE}.bak" ] && mv "${CONFIG_FILE}.bak" "$CONFIG_FILE" && systemctl restart gost
        journalctl -u gost -n 5 --no-pager
        read -p "  Press Enter..."
    fi
}

create_service() {
    GOST_BIN=$(command -v gost)
    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Gost V7 Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$GOST_BIN -C $CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable gost >/dev/null 2>&1
}

# ==================================================
#  INPUT HELPERS
# ==================================================
ask_input() { echo -ne "  ${HI_PINK}➤ $1 : ${NC}"; }
section_title() { echo -e "\n  ${BOLD}${HI_CYAN}:: $1 ::${NC}"; }
info_msg() { echo -e "  ${YELLOW}ℹ${NC} ${BLUE}$1${NC}"; }

# ==================================================
#  CORE FUNCTIONS
# ==================================================

add_tunnel() {
    draw_dashboard
    section_title "ADD DIRECT TUNNEL"
    info_msg "Relays traffic directly from Client to Destination."
    echo ""
    
    ask_input "Service Name"; read s_name
    check_name_safety "$s_name" || { sleep 2; return; }
    
    ask_input "Local Port"; read lport
    validate_port "$lport" || { echo "Bad Port"; sleep 2; return; }
    check_port_safety "$lport" || { sleep 2; return; }
    
    echo ""
    ask_input "Dest IP"; read raw_ip
    dip=$(normalize_ip "$raw_ip")
    ask_input "Dest Port"; read dport
    
    echo ""
    echo -e "  ${BOLD}Protocol Selection:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} TCP Only"
    echo -e "  ${HI_CYAN}[2]${NC} UDP Only"
    echo -e "  ${HI_CYAN}[3]${NC} Dual Stack ${HI_GREEN}(Recommended)${NC}"
    echo ""
    ask_input "Select"; read proto
    
    backup_config
    if [[ "$proto" == "1" || "$proto" == "3" ]]; then
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-tcp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"tcp\"}, \"listener\": {\"type\": \"tcp\"}, \"forwarder\": {\"nodes\": [{\"addr\": \"$dip:$dport\"}]}}]" "$CONFIG_FILE"
    fi
    if [[ "$proto" == "2" || "$proto" == "3" ]]; then
        $YQ_BIN -i ".services += [{\"name\": \"$s_name-udp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"udp\"}, \"listener\": {\"type\": \"udp\"}, \"forwarder\": {\"nodes\": [{\"addr\": \"$dip:$dport\"}]}}]" "$CONFIG_FILE"
    fi
    apply_config
}

add_lb() {
    draw_dashboard
    section_title "ADD LOAD BALANCER"
    info_msg "Distribute traffic between multiple servers."
    echo ""
    
    ask_input "Service Name"; read s_name
    check_name_safety "$s_name" || { sleep 2; return; }
    
    ask_input "Local Port"; read lport
    check_port_safety "$lport" || { sleep 2; return; }
    
    echo -e "\n  ${BOLD}Strategy:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} Round Robin   ${BLUE}Rotate IPs${NC}"
    echo -e "  ${HI_CYAN}[2]${NC} Random        ${BLUE}Random pick${NC}"
    echo -e "  ${HI_CYAN}[3]${NC} Least Conn    ${BLUE}Smart load${NC}"
    echo -e "  ${HI_CYAN}[4]${NC} Hashing       ${BLUE}Sticky IP${NC}"
    echo ""
    ask_input "Select"; read s_opt
    case $s_opt in 2) strat="random";; 3) strat="least";; 4) strat="hashing";; *) strat="round";; esac
    
    echo -e "\n  ${BOLD}Protocol:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} TCP Only"
    echo -e "  ${HI_CYAN}[2]${NC} UDP Only"
    echo -e "  ${HI_CYAN}[3]${NC} Dual Stack"
    echo ""
    ask_input "Select"; read proto

    declare -a NODES
    section_title "Manage Nodes"
    info_msg "Leave IP empty and press ENTER to finish."
    
    while true; do
        echo ""
        ask_input "Node IP"; read raw_nip
        [[ -z "$raw_nip" ]] && break
        nip=$(normalize_ip "$raw_nip")
        
        ask_input "Node Port"; read nport
        NODES+=("{\"addr\": \"$nip:$nport\"}")
        echo -e "    ${HI_GREEN}✔ Added${NC}"
    done
    
    if [ ${#NODES[@]} -eq 0 ]; then echo "No nodes!"; sleep 2; return; fi
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

add_secure() {
    draw_dashboard
    section_title "SECURE ENCRYPTED TUNNEL"
    info_msg "Hide traffic using TLS, WSS, or gRPC."
    echo ""
    
    echo -e "  ${HI_CYAN}[1]${NC} Sender / Client   ${BLUE}(Iran Server)${NC}"
    echo -e "  ${HI_CYAN}[2]${NC} Receiver / Server ${BLUE}(Foreign Server)${NC}"
    echo ""
    ask_input "Select Role"; read side
    
    if [[ "$side" == "1" ]]; then
        # Client
        section_title "SENDER CONFIGURATION"
        ask_input "Service Name"; read s_name
        check_name_safety "$s_name" || { sleep 2; return; }
        
        ask_input "Local Port"; read lport
        check_port_safety "$lport" || { sleep 2; return; }
        
        echo ""
        ask_input "Remote IP"; read raw_rip
        rip=$(normalize_ip "$raw_rip")
        ask_input "Remote Port"; read rport
        
        ask_input "SNI Domain"; read sni
        [[ -z "$sni" ]] && sni="google.com"
        
        echo -e "\n  ${BOLD}Encryption Type:${NC}"
        echo -e "  ${HI_CYAN}[1]${NC} WSS   ${BLUE}(Websocket Secure)${NC}"
        echo -e "  ${HI_CYAN}[2]${NC} gRPC  ${BLUE}(Google RPC)${NC}"
        echo -e "  ${HI_CYAN}[3]${NC} QUIC  ${BLUE}(UDP Transport)${NC}"
        echo ""
        ask_input "Select"; read t_opt
        case $t_opt in 2) tr="grpc";; 3) tr="quic";; *) tr="wss";; esac
        
        echo -e "\n  ${BOLD}Traffic Mode:${NC}"
        echo -e "  ${HI_CYAN}[1]${NC} TCP Only"
        echo -e "  ${HI_CYAN}[2]${NC} UDP Only"
        echo -e "  ${HI_CYAN}[3]${NC} Dual Stack ${HI_GREEN}(Best)${NC}"
        echo ""
        ask_input "Select"; read proto
        
        backup_config
        FWD_JSON="{\"nodes\": [{\"addr\": \"$rip:$rport\", \"connector\": {\"type\": \"relay\"}, \"dialer\": {\"type\": \"$tr\", \"tls\": {\"secure\": false, \"serverName\": \"$sni\"}}}]}"
        
        if [[ "$proto" == "1" || "$proto" == "3" ]]; then
            $YQ_BIN -i ".services += [{\"name\": \"$s_name-tcp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"tcp\"}, \"forwarder\": $FWD_JSON}]" "$CONFIG_FILE"
        fi
        if [[ "$proto" == "2" || "$proto" == "3" ]]; then
            $YQ_BIN -i ".services += [{\"name\": \"$s_name-udp\", \"addr\": \":$lport\", \"handler\": {\"type\": \"udp\"}, \"forwarder\": $FWD_JSON}]" "$CONFIG_FILE"
        fi
        apply_config

    elif [[ "$side" == "2" ]]; then
        # Server
        section_title "RECEIVER CONFIGURATION"
        ask_input "Service Name"; read s_name
        check_name_safety "$s_name" || { sleep 2; return; }
        
        ask_input "Secure Port"; read lport
        check_port_safety "$lport" || { sleep 2; return; }
        
        echo -e "\n  ${BOLD}Encryption Type:${NC}"
        echo -e "  ${HI_CYAN}[1]${NC} WSS"
        echo -e "  ${HI_CYAN}[2]${NC} gRPC"
        echo -e "  ${HI_CYAN}[3]${NC} QUIC"
        echo ""
        ask_input "Select"; read t_opt
        case $t_opt in 2) tr="grpc";; 3) tr="quic";; *) tr="wss";; esac
        
        echo ""
        ask_input "Forward IP"; read raw_tip
        tip=$(normalize_ip "$raw_tip")
        ask_input "Forward Port"; read tport
        
        ask_input "Cert Domain"; read cert_cn
        [[ -z "$cert_cn" ]] && cert_cn="update.microsoft.com"

        # Generate Certs
        local c_path="$CERT_DIR/cert_${lport}.pem"
        local k_path="$CERT_DIR/key_${lport}.pem"
        echo -e "  ${BLUE}Generating Certificates...${NC}"
        openssl req -newkey rsa:2048 -nodes -keyout "$k_path" -x509 -days 3650 -out "$c_path" -subj "/CN=$cert_cn" > /dev/null 2>&1
        chmod 600 "$k_path"
        
        backup_config
        
        s_name="$s_name" lport=":$lport" tr="$tr" taddr="$tip:$tport" cert="$c_path" key="$k_path" \
        $YQ_BIN -i '.services += [{"name": env(s_name), "addr": env(lport), "handler": {"type": "relay"}, "listener": {"type": env(tr), "tls": {"certFile": env(cert), "keyFile": env(key)}}, "forwarder": {"nodes": [{"addr": env(taddr)}]}}]' "$CONFIG_FILE"
        apply_config
    fi
}

delete_service() {
    draw_dashboard
    section_title "DELETE SERVICE"
    
    count=$($YQ_BIN '.services | length' "$CONFIG_FILE")
    if [[ "$count" == "0" ]]; then echo "No services configured."; sleep 2; return; fi
    
    # Table
    printf "  ${BLUE}%-4s %-25s %-15s${NC}\n" "ID" "NAME" "PORT"
    echo -e "  ${BLUE}────────────────────────────────────────────${NC}"
    
    for ((i=0; i<$count; i++)); do
        s_name=$($YQ_BIN ".services[$i].name" "$CONFIG_FILE" | tr -d '"')
        s_port=$($YQ_BIN ".services[$i].addr" "$CONFIG_FILE" | tr -d '"')
        printf "  ${HI_CYAN}[%d]${NC}  ${BOLD}%-25s${NC} %-15s\n" "$i" "$s_name" "$s_port"
    done
    
    echo ""
    ask_input "Enter ID (c to cancel)"; read del_id
    if [[ "$del_id" =~ ^[0-9]+$ ]] && [ "$del_id" -lt "$count" ]; then
        backup_config
        $YQ_BIN -i "del(.services[$del_id])" "$CONFIG_FILE"
        apply_config
    fi
}

menu_uninstall() {
    ask_input "Uninstall Everything? (y/n)"; read c
    if [[ "$c" == "y" ]]; then
        systemctl stop gost; systemctl disable gost
        rm -rf "$CONFIG_DIR" "$SERVICE_FILE" "$YQ_BIN"
        systemctl daemon-reload
        rm -f "$(command -v gost)"
        echo -e "\n  ${HI_GREEN}✔ Uninstalled successfully.${NC}"; exit 0
    fi
}

# ==================================================
#  MAIN LOOP
# ==================================================

install_dependencies
create_service

while true; do
    draw_dashboard
    read opt
    case $opt in
        1) add_tunnel ;;
        2) add_secure ;;
        3) add_lb ;;
        4) delete_service ;;
        5) backup_config; nano "$CONFIG_FILE"; apply_config ;;
        6) journalctl -u gost -f ;;
        7) menu_uninstall ;;
        0) exit 0 ;;
        *) sleep 0.5 ;;
    esac
done