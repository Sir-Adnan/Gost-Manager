#!/bin/bash

# ==================================================
# Gost Manager - TURBO EDITION (v9.0 Final)
# Creator: UnknownZero
# Focus: Mux, KCP/H2/SS, DNS, Proxy, Fixes
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
    echo -e "    ${PURPLE}M  A  N  A  G  E  R    ${BOLD}v 9 . 0${NC}"
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
    echo -e "  ${RED}⚠ WARNING:${NC} ${YELLOW}Use only A-Z, 0-9. NO special chars ( \" ' $ \ )!${NC}"
}

draw_dashboard() {
    clear
    draw_logo
    draw_line
    
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

    echo -e "  ${ICON_NET} IP: ${BOLD}${SERVER_IP}${NC}"
    echo -e "  ${ICON_RAM} RAM: ${BOLD}${RAM_USAGE}${NC}   ${ICON_CPU} Load: ${BOLD}${LOAD}${NC}"
    echo -e "  ${ICON_GEAR} Status: ${STATUS}   ${ICON_ROCKET} Tunnels: ${HI_GREEN}${TUNNELS}${NC}"
    
    draw_line
    echo ""
    
    print_option "1" "$ICON_ROCKET" "Direct Tunnel" "Simple / mTCP"
    print_option "2" "$ICON_LOCK" "Secure Tunnel" "WSS/KCP/H2/SS"
    print_option "3" "$ICON_LB" "Load Balancer" "Multi-node Dist"
    print_option "4" "$ICON_PROXY" "Simple Proxy" "SOCKS5 / HTTP"
    print_option "5" "$ICON_DNS" "Secure DNS" "DoH / UDP"
    print_option "6" "$ICON_TRASH" "Delete Service" "Remove Active"
    print_option "7" "$ICON_GEAR" "Edit Config" "Manual (Nano)"
    print_option "8" "$ICON_LOGS" "View Logs" "Live Monitor"
    print_option "9" "$ICON_RESTART" "Auto-Restart" "Watchdog (CPU)"
    print_option "10" "$ICON_TRASH" "Uninstall" "Remove All"
    print_option "0" "$ICON_EXIT" "Exit" "Close Script"
    
    echo ""
    draw_line
    printf "  ${HI_PINK}➤ Select Option : ${NC}"
}

# ==================================================
#  HELPER FUNCTIONS
# ==================================================

install_dependencies() {
    local NEED_INSTALL=false
    if ! command -v curl &> /dev/null || ! command -v openssl &> /dev/null || ! command -v lsof &> /dev/null || ! command -v nc &> /dev/null || ! command -v bc &> /dev/null; then
        NEED_INSTALL=true
    fi

    if [ "$NEED_INSTALL" = true ]; then
        echo -e "${BLUE}Installing core dependencies...${NC}"
        apt-get update -q && apt-get install -y curl openssl lsof nano netcat-openbsd vnstat bc -q
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

setup_shortcut() {
    if [ ! -s "$SHORTCUT_BIN" ]; then
        echo ""
        draw_line
        echo -e "  ${ICON_INSTALL}  ${BOLD}Setup 'igost' Shortcut?${NC}"
        echo -e "  ${BLUE}Allows you to run the manager by typing 'igost'.${NC}"
        echo ""
        
        echo -ne "  ${HI_PINK}➤ Install (Y/n)? : ${NC}"
        read install_opt
        install_opt=${install_opt:-y}
        
        if [[ "$install_opt" =~ ^[Yy]$ ]]; then
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
Description=Gost Service High Performance
After=network.target

[Service]
Type=simple
User=root
# Performance Tuning
Environment="GOGC=20"
ExecStart=$GOST_BIN -C $CONFIG_FILE --log.level=fatal
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

ask_input() { echo -ne "  ${HI_PINK}➤ $1 : ${NC}"; }
section_title() { echo -e "\n  ${BOLD}${HI_CYAN}:: $1 ::${NC}"; }
info_msg() { echo -e "  ${YELLOW}ℹ${NC} ${BLUE}$1${NC}"; }

# ==================================================
#  CORE FUNCTIONS (v9.0)
# ==================================================

add_tunnel() {
    draw_dashboard
    section_title "ADD DIRECT TUNNEL"
    show_guide "Direct Tunnel & mTCP" \
    "Use this for simple forwarding (Relay).\n  ${BOLD}[1-2] TCP/UDP:${NC} Standard forwarding.\n  ${BOLD}[3] mTCP:${NC} (Turbo) Sends multiple requests in one connection."
    
    show_warning
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
    echo -e "  ${HI_CYAN}[3]${NC} mTCP ${HI_PINK}(Turbo Multiplex)${NC}"
    echo -e "  ${HI_CYAN}[4]${NC} Dual Stack ${HI_GREEN}(TCP+UDP)${NC}"
    echo ""
    ask_input "Select"; read proto
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
    ask_input "Select Role"; read side
    
    if [[ "$side" == "1" ]]; then
        section_title "SENDER CONFIGURATION"
        show_warning
        echo ""
        ask_input "Service Name"; read s_name
        check_name_safety "$s_name" || { sleep 2; return; }
        ask_input "Local Port"; read lport
        check_port_safety "$lport" || { sleep 2; return; }
        echo ""
        ask_input "Remote IP"; read raw_rip
        rip=$(normalize_ip "$raw_rip")
        ask_input "Remote Port"; read rport
        
        ask_input "SNI Domain (Optional)"; read sni
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
        ask_input "Select"; read t_opt
        
        case $t_opt in 
            2) tr="mwss";; 3) tr="grpc";; 4) tr="quic";; 5) tr="h2";; 6) tr="kcp";; 7) tr="ss";; *) tr="wss";; 
        esac

        extra_meta=""
        if [[ "$tr" == "ss" ]]; then
            echo -e "\n  ${BOLD}Cipher:${NC}"
            echo -e "  ${HI_CYAN}[1]${NC} AES-256-GCM"
            echo -e "  ${HI_CYAN}[2]${NC} Chacha20-IETF-Poly1305"
            echo -e "  ${HI_CYAN}[3]${NC} None"
            ask_input "Select"; read c_opt
            case $c_opt in 2) cipher="chacha20-ietf-poly1305";; 3) cipher="none";; *) cipher="aes-256-gcm";; esac
            
            ask_input "Password"; read ss_pass
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
        ask_input "Service Name"; read s_name
        check_name_safety "$s_name" || { sleep 2; return; }
        ask_input "Secure Port"; read lport
        check_port_safety "$lport" || { sleep 2; return; }
        
        echo -e "\n  ${BOLD}Protocol:${NC}"
        echo -e "  ${HI_CYAN}[1]${NC} WSS"
        echo -e "  ${HI_CYAN}[2]${NC} mWSS ${HI_PINK}(Turbo)${NC}"
        echo -e "  ${HI_CYAN}[3]${NC} gRPC"
        echo -e "  ${HI_CYAN}[4]${NC} QUIC"
        echo -e "  ${HI_CYAN}[5]${NC} H2"
        echo -e "  ${HI_CYAN}[6]${NC} KCP"
        echo -e "  ${HI_CYAN}[7]${NC} Shadowsocks"
        echo ""
        ask_input "Select"; read t_opt
        case $t_opt in 
            2) tr="mwss";; 3) tr="grpc";; 4) tr="quic";; 5) tr="h2";; 6) tr="kcp";; 7) tr="ss";; *) tr="wss";; 
        esac

        if [[ "$tr" == "ss" ]]; then
            echo -e "\n  ${BOLD}Cipher:${NC}"
            echo -e "  ${HI_CYAN}[1]${NC} AES-256-GCM"
            echo -e "  ${HI_CYAN}[2]${NC} Chacha20-IETF-Poly1305"
            echo -e "  ${HI_CYAN}[3]${NC} None"
            ask_input "Select"; read c_opt
            case $c_opt in 2) cipher="chacha20-ietf-poly1305";; 3) cipher="none";; *) cipher="aes-256-gcm";; esac
            
            ask_input "Password"; read ss_pass
            tr="shadowsocks"
        else
            echo ""
            ask_input "Forward IP"; read raw_tip
            tip=$(normalize_ip "$raw_tip")
            ask_input "Forward Port"; read tport
            
            ask_input "Cert Domain"; read cert_cn
            [[ -z "$cert_cn" ]] && cert_cn="update.microsoft.com"
            
            local c_path="$CERT_DIR/cert_${lport}.pem"
            local k_path="$CERT_DIR/key_${lport}.pem"
            echo -e "  ${BLUE}Generating Certificates...${NC}"
            openssl req -newkey rsa:2048 -nodes -keyout "$k_path" -x509 -days 3650 -out "$c_path" -subj "/CN=$cert_cn" > /dev/null 2>&1
            chmod 600 "$k_path"
        fi

        backup_config
        
        if [[ "$tr" == "shadowsocks" ]]; then
             ask_input "Forward IP"; read raw_tip
             tip=$(normalize_ip "$raw_tip")
             ask_input "Forward Port"; read tport
             
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

add_simple_proxy() {
    draw_dashboard
    section_title "SIMPLE PROXY SERVER"
    show_guide "Proxy Mode" \
    "Turns this server into a direct proxy.\n  ${BOLD}SOCKS5 / HTTP:${NC} Use these in Telegram, Browser, or Apps.\n  ${BOLD}Auth:${NC} Set Username/Password for security."
    
    show_warning
    echo ""
    ask_input "Service Name"; read s_name
    check_name_safety "$s_name" || { sleep 2; return; }
    ask_input "Port"; read lport
    check_port_safety "$lport" || { sleep 2; return; }
    
    echo -e "\n  ${BOLD}Type:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} SOCKS5"
    echo -e "  ${HI_CYAN}[2]${NC} HTTP"
    ask_input "Select"; read p_opt
    
    ask_input "Username (Leave empty for none)"; read p_user
    if [[ -n "$p_user" ]]; then
        ask_input "Password"; read p_pass
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
    "Sets up a DNS resolver on your server.\n  ${BOLD}Prevent Leaks:${NC} Forwards DNS queries securely to Cloudflare/Google.\n  ${BOLD}Protocol:${NC} Listens on UDP/TCP 53 (Standard)."
    
    ask_input "Service Name"; read s_name
    check_name_safety "$s_name" || { sleep 2; return; }
    ask_input "Local Port (Default 53)"; read lport
    [[ -z "$lport" ]] && lport="53"
    check_port_safety "$lport" || { sleep 2; return; }
    
    echo -e "\n  ${BOLD}Upstream Provider:${NC}"
    echo -e "  ${HI_CYAN}[1]${NC} Cloudflare (1.1.1.1)"
    echo -e "  ${HI_CYAN}[2]${NC} Google (8.8.8.8)"
    echo -e "  ${HI_CYAN}[3]${NC} Custom"
    ask_input "Select"; read d_opt
    
    case $d_opt in
        1) up_dns="1.1.1.1";;
        2) up_dns="8.8.8.8";;
        *) ask_input "Enter DNS IP"; read up_dns;;
    esac
    
    backup_config
    $YQ_BIN -i ".services += [{\"name\": \"$s_name\", \"addr\": \":$lport\", \"handler\": {\"type\": \"dns\"}, \"listener\": {\"type\": \"udp\"}, \"forwarder\": {\"nodes\": [{\"addr\": \"$up_dns:53\"}]}}]" "$CONFIG_FILE"
    
    apply_config
}

delete_service() {
    draw_dashboard
    section_title "DELETE SERVICE"
    count=$($YQ_BIN '.services | length' "$CONFIG_FILE")
    if [[ "$count" == "0" ]]; then echo "No services configured."; sleep 2; return; fi
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

setup_watchdog() {
    draw_dashboard
    section_title "CPU OVERLOAD WATCHDOG"
    info_msg "Automatically restarts Gost if CPU usage hits High Load."
    echo ""
    echo -e "  ${YELLOW}This will create a background job checking CPU every minute.${NC}"
    echo ""
    
    ask_input "Enable Watchdog? (y/n)"; read confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then return; fi
    
    # Create the watchdog script
    cat <<EOF > /usr/local/bin/gost_watchdog.sh
#!/bin/bash
CPU_IDLE=\$(top -bn2 -d 0.5 | grep "Cpu(s)" | tail -n 1 | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print \$1}')
CPU_USAGE=\$(echo "100 - \$CPU_IDLE" | bc -l 2>/dev/null | cut -d. -f1)
CPU_USAGE=\${CPU_USAGE:-0}
if [ "\$CPU_USAGE" -ge 95 ]; then
    systemctl restart gost
    echo "\$(date): CPU Critical (\$CPU_USAGE%). Gost Service Restarted." >> /var/log/gost_watchdog.log
fi
EOF
    chmod +x /usr/local/bin/gost_watchdog.sh
    
    if ! command -v bc &> /dev/null; then apt-get install -y bc > /dev/null 2>&1; fi
    (crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/gost_watchdog.sh") | sort -u | crontab -
    
    echo -e "\n  ${HI_GREEN}✔ Watchdog Activated successfully.${NC}"
    sleep 2
}

menu_uninstall() {
    draw_dashboard
    section_title "UNINSTALL MANAGER"
    echo -e "  ${RED}⚠ WARNING: This will remove Gost, all configs, and this script!${NC}"
    echo ""
    ask_input "Are you sure? (type 'yes' to confirm)"; read c
    if [[ "$c" == "yes" ]]; then
        systemctl stop gost; systemctl disable gost
        rm -f /usr/local/bin/gost_watchdog.sh
        crontab -l | grep -v "gost_watchdog.sh" | crontab -
        rm -rf "$CONFIG_DIR" "$SERVICE_FILE" "$YQ_BIN" "$SHORTCUT_BIN"
        systemctl daemon-reload
        rm -f "$(command -v gost)"
        echo -e "\n  ${HI_GREEN}✔ Uninstalled successfully.${NC}"; exit 0
    fi
}

menu_exit() {
    clear
    echo -e "\n  ${HI_PINK}Goodbye! 👋${NC}"
    exit 0
}

# ==================================================
#  MAIN LOOP
# ==================================================

install_dependencies
create_service
setup_shortcut

while true; do
    draw_dashboard
    read opt
    case $opt in
        1) add_tunnel ;;
        2) add_secure ;;
        3) add_lb ;;
        4) add_simple_proxy ;;
        5) setup_dns ;;
        6) delete_service ;;
        7) backup_config; nano "$CONFIG_FILE"; apply_config ;;
        8) journalctl -u gost -f ;;
        9) setup_watchdog ;;
        10) menu_uninstall ;;
        0) menu_exit ;;
        *) sleep 0.5 ;;
    esac
done
