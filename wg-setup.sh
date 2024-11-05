#!/bin/bash

set -euo pipefail

VPN_INTERFACE="${VPN_INTERFACE:-}"

MAIN_INTERFACE="eth0"
WG_PROXY_INTERFACE="wg-proxy"
WG_NOPROXY_INTERFACE="wg-noproxy"
PROXY_PORT="8081"
WG_PROXY_PORT="51820"
WG_NOPROXY_PORT="51821"
WG_CONFIG_DIR="/etc/wireguard"

HTTP_PORTS=(80 443)

WG_PROXY_SUBNET_IPV4="10.0.0.0/24"
WG_NOPROXY_SUBNET_IPV4="10.0.1.0/24"
WG_PROXY_SUBNET_IPV6="fd00:0:0:1::/64"
WG_NOPROXY_SUBNET_IPV6="fd00:0:0:2::/64"

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --default-setup                 Perform default setup (create servers and add Android/iOS clients)"
    echo "  --setup-servers                 Setup WireGuard servers"
    echo "  --http-ports <ports>            Comma-separated list of HTTP(S) ports to redirect (e.g., 80,443,8080)"
    echo "  --add-client                    Add a client"
    echo "    --interface <interface>       Specify WireGuard interface (wg-proxy or wg-noproxy)"
    echo "    --client-name <name>          Specify client name"
    echo "  --list-clients                  List existing clients"
    echo "  --vpn-interface <interface>     Specify VPN interface"
    echo "  --main-interface <interface>    Specify main network interface (default: eth0)"
    echo "  --help                          Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --default-setup"
    echo "  $0 --default-setup --http-ports 80,443,8080,8443"
    echo "  $0 --setup-servers"
    echo "  $0 --add-client --interface wg-proxy --client-name mydevice"
    echo "  $0 --list-clients"
    exit 1
}

ARGS=("$@")
NUM_ARGS=$#
i=0
while [ $i -lt $NUM_ARGS ]; do
    case "${ARGS[$i]}" in
    --default-setup)
        ACTION="default_setup"
        ;;
    --setup-servers)
        ACTION="setup_servers"
        ;;
    --http-ports)
        i=$((i + 1))
        HTTP_PORTS_CSV="${ARGS[$i]}"
        IFS=',' read -r -a HTTP_PORTS <<<"$HTTP_PORTS_CSV"
        ;;
    --add-client)
        ACTION="add_client_cmd"
        ;;
    --list-clients)
        ACTION="list_clients"
        ;;
    --vpn-interface)
        i=$((i + 1))
        VPN_INTERFACE="${ARGS[$i]}"
        ;;
    --main-interface)
        i=$((i + 1))
        MAIN_INTERFACE="${ARGS[$i]}"
        ;;
    --interface)
        i=$((i + 1))
        CLIENT_INTERFACE="${ARGS[$i]}"
        ;;
    --client-name)
        i=$((i + 1))
        CLIENT_NAME="${ARGS[$i]}"
        ;;
    --help)
        usage
        ;;
    *)
        echo "Unknown option: ${ARGS[$i]}"
        usage
        ;;
    esac
    i=$((i + 1))
done

print_next_steps() {
    echo
    echo "Important steps for the proxying setup:"
    echo "1. Configure Burp Suite to listen on <wg-proxy-ip>:${PROXY_PORT} and enable 'Support invisible proxying'"
    echo "2. Install Burp's CA certificate on your mobile devices"
    echo "3. Install the WireGuard app on your devices"
    echo "4. Scan the QR codes in the WireGuard apps to import the client configurations"
}

cleanup() {
    print_next_steps
    exit 0
}

trap cleanup SIGINT

get_host_ip() {
    local interface=$1
    local host_ip

    host_ip=$(ip -4 addr show "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [ -z "$host_ip" ]; then
        echo "Could not get IP from $interface"
        exit 1
    fi

    echo "$host_ip"
}

HOST_IP=$(get_host_ip "$MAIN_INTERFACE")

check_dependencies() {
    packages=("wireguard-tools" "qrencode")
    missing_packages=()

    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            echo "$pkg is not installed"
            missing_packages+=("$pkg")
        fi
    done

    if [ ${#missing_packages[@]} -ne 0 ]; then
        echo "Installing missing packages: ${missing_packages[*]}"
        apt update
        apt install -y "${missing_packages[@]}"
    fi
}

detect_vpn_interface() {
    if [ -n "$VPN_INTERFACE" ]; then
        if ip link show "$VPN_INTERFACE" &>/dev/null; then
            echo "Using preconfigured VPN interface: $VPN_INTERFACE"
        else
            echo "Error: Specified VPN interface '$VPN_INTERFACE' does not exist."
            exit 1
        fi
    else
        local interfaces=()

        # List all network interfaces except loopback and physical interfaces
        mapfile -t interfaces < <(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(tun|vpn|ppp|wg|tap)[0-9]+')

        if [ "${#interfaces[@]}" -eq 0 ]; then
            echo "No VPN interfaces detected. Please connect to your VPN or preconfigure the VPN_INTERFACE variable and re-run the script."
            exit 1
        elif [ "${#interfaces[@]}" -eq 1 ]; then
            VPN_INTERFACE="${interfaces[0]}"
            echo "Detected VPN interface: $VPN_INTERFACE"
        else
            echo "Multiple VPN interfaces detected:"
            select iface in "${interfaces[@]}"; do
                if [ -n "$iface" ]; then
                    VPN_INTERFACE="$iface"
                    echo "Selected VPN interface: $VPN_INTERFACE"
                    break
                else
                    echo "Invalid selection. Please try again."
                fi
            done
        fi
    fi
}

generate_server_keys() {
    local private_key public_key
    private_key=$(wg genkey)
    public_key=$(echo "$private_key" | wg pubkey)
    echo "$private_key:$public_key"
}

enable_wg_on_boot() {
    local interface="$1"
    echo "Enabling WireGuard interface $interface to start on boot..."
    systemctl enable "wg-quick@$interface"
}

create_server_config() {
    local interface=$1
    local proxy_enabled=$2
    local server_private_key=$3
    local server_public_key=$4
    local subnet_ipv4=$5
    local subnet_ipv6=$6
    local port=$7
    local config_path="${WG_CONFIG_DIR}/${interface}.conf"
    local post_up_commands=()
    local post_down_commands=()

    if [ -f "$config_path" ]; then
        local backup_config="${config_path}.bak.$(date +%Y%m%d%H%M%S)"
        echo "Backing up existing configuration file to $backup_config"
        cp "$config_path" "$backup_config"
    fi

    # Extract network base and netmask for IPv4
    local network_base_ipv4=$(echo "$subnet_ipv4" | cut -d'/' -f1)
    local netmask_length_ipv4=$(echo "$subnet_ipv4" | cut -d'/' -f2)
    IFS='.' read -r i1 i2 i3 i4 <<<"$network_base_ipv4"
    local server_ip_ipv4="$i1.$i2.$i3.$((i4 + 1))/$netmask_length_ipv4"

    # Extract network base and netmask for IPv6
    local network_base_ipv6=$(echo "$subnet_ipv6" | cut -d'/' -f1)
    local netmask_length_ipv6=$(echo "$subnet_ipv6" | cut -d'/' -f2)
    local server_ip_ipv6="${network_base_ipv6}1/$netmask_length_ipv6"

    {
        echo "[Interface]"
        echo "Address = $server_ip_ipv4, $server_ip_ipv6"
        echo "ListenPort = $port"
        echo "PrivateKey = $server_private_key"
    } >"$config_path"

    post_up_commands+=("sysctl -w net.ipv4.ip_forward=1")
    post_up_commands+=("sysctl -w net.ipv6.conf.all.forwarding=1")

    if [ "$proxy_enabled" == "yes" ]; then
        for http_port in "${HTTP_PORTS[@]}"; do
            post_up_commands+=("iptables -t nat -A PREROUTING -i $interface -p tcp --dport $http_port -j REDIRECT --to-port $PROXY_PORT")
            post_down_commands+=("iptables -t nat -D PREROUTING -i $interface -p tcp --dport $http_port -j REDIRECT --to-port $PROXY_PORT")

            post_up_commands+=("ip6tables -t nat -A PREROUTING -i $interface -p tcp --dport $http_port -j REDIRECT --to-port $PROXY_PORT")
            post_down_commands+=("ip6tables -t nat -D PREROUTING -i $interface -p tcp --dport $http_port -j REDIRECT --to-port $PROXY_PORT")
        done
    fi

    post_up_commands+=("iptables -A FORWARD -i $interface -o $VPN_INTERFACE -j ACCEPT")
    post_up_commands+=("iptables -A FORWARD -i $VPN_INTERFACE -o $interface -j ACCEPT")
    post_down_commands+=("iptables -D FORWARD -i $interface -o $VPN_INTERFACE -j ACCEPT")
    post_down_commands+=("iptables -D FORWARD -i $VPN_INTERFACE -o $interface -j ACCEPT")

    post_up_commands+=("ip6tables -A FORWARD -i $interface -o $VPN_INTERFACE -j ACCEPT")
    post_up_commands+=("ip6tables -A FORWARD -i $VPN_INTERFACE -o $interface -j ACCEPT")
    post_down_commands+=("ip6tables -D FORWARD -i $interface -o $VPN_INTERFACE -j ACCEPT")
    post_down_commands+=("ip6tables -D FORWARD -i $VPN_INTERFACE -o $interface -j ACCEPT")

    post_up_commands+=("iptables -t nat -A POSTROUTING -o $VPN_INTERFACE -s $subnet_ipv4 -j MASQUERADE")
    post_down_commands+=("iptables -t nat -D POSTROUTING -o $VPN_INTERFACE -s $subnet_ipv4 -j MASQUERADE")

    post_up_commands+=("ip6tables -t nat -A POSTROUTING -o $VPN_INTERFACE -s $subnet_ipv6 -j MASQUERADE")
    post_down_commands+=("ip6tables -t nat -D POSTROUTING -o $VPN_INTERFACE -s $subnet_ipv6 -j MASQUERADE")

    for cmd in "${post_up_commands[@]}"; do
        echo "PostUp = $cmd" >>"$config_path"
    done

    for cmd in "${post_down_commands[@]}"; do
        echo "PostDown = $cmd" >>"$config_path"
    done

    chmod 600 "$config_path"
}

get_next_available_ip() {
    local subnet_ipv4=$1
    local subnet_ipv6=$2
    local interface=$3
    local config_path="${WG_CONFIG_DIR}/${interface}.conf"

    # Extract network base and netmask for IPv4
    local network_base_ipv4=$(echo "$subnet_ipv4" | cut -d'/' -f1)
    local netmask_length_ipv4=$(echo "$subnet_ipv4" | cut -d'/' -f2)
    IFS='.' read -r i1 i2 i3 i4 <<<"$network_base_ipv4"

    # Extract network base and netmask for IPv6
    local network_base_ipv6=$(echo "$subnet_ipv6" | cut -d'/' -f1)
    local netmask_length_ipv6=$(echo "$subnet_ipv6" | cut -d'/' -f2)

    # Extract existing IPs from the server configuration
    local existing_ips=()
    if [ -f "$config_path" ]; then
        existing_ips=($(grep 'AllowedIPs' "$config_path" | awk '{print $3}' | cut -d',' -f1 | cut -d'/' -f1))
        local server_ips=$(grep 'Address' "$config_path" | awk '{print $3}')
        IFS=',' read -ra ADDR <<<"$server_ips"
        for addr in "${ADDR[@]}"; do
            existing_ips+=("$(echo "$addr" | cut -d'/' -f1)")
        done
    fi

    # Generate possible IPs in the subnets
    local available_ip_ipv4=""
    local available_ip_ipv6=""
    for ((i = i4 + 2; i <= 254; i++)); do
        ip_ipv4="$i1.$i2.$i3.$i"
        ip_ipv6="${network_base_ipv6}$i"

        local ip_in_use=false
        for existing_ip in "${existing_ips[@]}"; do
            if [[ "$existing_ip" == "$ip_ipv4" || "$existing_ip" == "$ip_ipv6" ]]; then
                ip_in_use=true
                break
            fi
        done

        if [[ "$ip_in_use" == false ]]; then
            available_ip_ipv4="$ip_ipv4/$netmask_length_ipv4"
            available_ip_ipv6="$ip_ipv6/$netmask_length_ipv6"
            break
        fi
    done

    if [ -z "$available_ip_ipv4" ] || [ -z "$available_ip_ipv6" ]; then
        echo "No available IP addresses in subnets $subnet_ipv4 and $subnet_ipv6"
        exit 1
    fi

    echo "$available_ip_ipv4,$available_ip_ipv6"
}

add_client() {
    local interface=$1
    local client_name=$2
    local server_public_key=$3
    local port=$4
    local subnet_ipv4
    local subnet_ipv6

    if [ "$interface" == "$WG_PROXY_INTERFACE" ]; then
        subnet_ipv4="$WG_PROXY_SUBNET_IPV4"
        subnet_ipv6="$WG_PROXY_SUBNET_IPV6"
    else
        subnet_ipv4="$WG_NOPROXY_SUBNET_IPV4"
        subnet_ipv6="$WG_NOPROXY_SUBNET_IPV6"
    fi

    local client_ips
    client_ips=$(get_next_available_ip "$subnet_ipv4" "$subnet_ipv6" "$interface")
    IFS=',' read -r client_ip_ipv4 client_ip_ipv6 <<<"$client_ips"

    local config_path="${WG_CONFIG_DIR}/${interface}.conf"
    local client_private_key client_public_key client_config client_config_file

    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)

    {
        echo ""
        echo "[Peer]"
        echo "PublicKey = $client_public_key"
        echo "AllowedIPs = ${client_ip_ipv4%/*}/32, ${client_ip_ipv6%/*}/128"
    } >>"$config_path"

    wg set "$interface" peer "$client_public_key" allowed-ips "${client_ip_ipv4%/*}/32,${client_ip_ipv6%/*}/128"

    client_config="# $client_name-$interface
[Interface]
Address = $client_ip_ipv4, $client_ip_ipv6
PrivateKey = $client_private_key
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = $server_public_key
Endpoint = $HOST_IP:$port
AllowedIPs = 0.0.0.0/0, ::/0"

    client_config_file="${client_name}-${interface}.conf"
    echo "$client_config" >"$client_config_file"
    chmod 600 "$client_config_file"

    echo "Client configuration for $client_name-$interface saved to $client_config_file"
    echo "Displaying QR code for $client_name-$interface:"
    qrencode -t ansiutf8 <"$client_config_file"
    qrencode -o "${client_name}-${interface}.png" <"$client_config_file"
    echo "QR code image saved to ${client_name}-${interface}.png"
}

default_setup() {
    echo "Performing default setup..."
    setup_servers

    echo "Adding Android and iOS clients to both servers..."

    proxy_public_key=$(wg show "$WG_PROXY_INTERFACE" public-key)
    noproxy_public_key=$(wg show "$WG_NOPROXY_INTERFACE" public-key)

    add_client "$WG_PROXY_INTERFACE" "android" "$proxy_public_key" "$WG_PROXY_PORT"
    add_client "$WG_NOPROXY_INTERFACE" "android" "$noproxy_public_key" "$WG_NOPROXY_PORT"

    add_client "$WG_PROXY_INTERFACE" "ios" "$proxy_public_key" "$WG_PROXY_PORT"
    add_client "$WG_NOPROXY_INTERFACE" "ios" "$noproxy_public_key" "$WG_NOPROXY_PORT"

    echo "Default setup complete."
}

setup_servers() {
    detect_vpn_interface
    check_dependencies

    if ip link show "$WG_PROXY_INTERFACE" &>/dev/null; then
        echo "Bringing down existing interface $WG_PROXY_INTERFACE"
        wg-quick down "$WG_PROXY_INTERFACE"
    fi

    if ip link show "$WG_NOPROXY_INTERFACE" &>/dev/null; then
        echo "Bringing down existing interface $WG_NOPROXY_INTERFACE"
        wg-quick down "$WG_NOPROXY_INTERFACE"
    fi

    if [ -f "${WG_CONFIG_DIR}/${WG_PROXY_INTERFACE}.conf" ]; then
        local backup_proxy_conf="${WG_CONFIG_DIR}/${WG_PROXY_INTERFACE}.conf.bak.$(date +%Y%m%d%H%M%S)"
        echo "Backing up existing proxy configuration to $backup_proxy_conf"
        cp "${WG_CONFIG_DIR}/${WG_PROXY_INTERFACE}.conf" "$backup_proxy_conf"
    fi

    if [ -f "${WG_CONFIG_DIR}/${WG_NOPROXY_INTERFACE}.conf" ]; then
        local backup_noproxy_conf="${WG_CONFIG_DIR}/${WG_NOPROXY_INTERFACE}.conf.bak.$(date +%Y%m%d%H%M%S)"
        echo "Backing up existing non-proxy configuration to $backup_noproxy_conf"
        cp "${WG_CONFIG_DIR}/${WG_NOPROXY_INTERFACE}.conf" "$backup_noproxy_conf"
    fi

    IFS=":" read -r proxy_private_key proxy_public_key <<<"$(generate_server_keys)"
    IFS=":" read -r noproxy_private_key noproxy_public_key <<<"$(generate_server_keys)"

    create_server_config "$WG_PROXY_INTERFACE" "yes" "$proxy_private_key" "$proxy_public_key" "$WG_PROXY_SUBNET_IPV4" "$WG_PROXY_SUBNET_IPV6" "$WG_PROXY_PORT"
    create_server_config "$WG_NOPROXY_INTERFACE" "no" "$noproxy_private_key" "$noproxy_public_key" "$WG_NOPROXY_SUBNET_IPV4" "$WG_NOPROXY_SUBNET_IPV6" "$WG_NOPROXY_PORT"

    wg-quick up "$WG_PROXY_INTERFACE"
    wg-quick up "$WG_NOPROXY_INTERFACE"

    enable_wg_on_boot "$WG_PROXY_INTERFACE"
    enable_wg_on_boot "$WG_NOPROXY_INTERFACE"

    echo "WireGuard servers are set up and running."
}

add_client_menu() {
    echo "Available servers:"
    echo "1) Proxy Server ($WG_PROXY_INTERFACE)"
    echo "2) Non-Proxy Server ($WG_NOPROXY_INTERFACE)"
    read -rp "Choose a server to add the client to (1 or 2): " server_choice
    case $server_choice in
    1)
        interface="$WG_PROXY_INTERFACE"
        port="$WG_PROXY_PORT"
        ;;
    2)
        interface="$WG_NOPROXY_INTERFACE"
        port="$WG_NOPROXY_PORT"
        ;;
    *)
        echo "Invalid choice"
        return
        ;;
    esac

    while true; do
        read -rp "Enter client name: " client_name
        client_name="$(echo -e "${client_name}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        if [ -z "$client_name" ]; then
            echo "Client name cannot be empty. Please enter a valid client name."
        elif [[ "$client_name" =~ [^a-zA-Z0-9_-] ]]; then
            echo "Client name contains invalid characters. Please use only letters, numbers, underscores, or hyphens."
        else
            client_config_file="${client_name}-${interface}.conf"
            if [ -f "$client_config_file" ]; then
                echo "A client with the name '$client_name' already exists. Please choose a different name."
            else
                break
            fi
        fi
    done

    server_public_key=$(wg show "$interface" public-key)

    add_client "$interface" "$client_name" "$server_public_key" "$port"
}

add_client_cmd() {
    if [ -z "${CLIENT_NAME:-}" ]; then
        echo "Error: --client-name is required for --add-client"
        usage
    fi
    if [ -z "${CLIENT_INTERFACE:-}" ]; then
        echo "Error: --interface is required for --add-client"
        usage
    fi

    if [ "$CLIENT_INTERFACE" != "$WG_PROXY_INTERFACE" ] && [ "$CLIENT_INTERFACE" != "$WG_NOPROXY_INTERFACE" ]; then
        echo "Error: Invalid interface '$CLIENT_INTERFACE'. Valid options are '$WG_PROXY_INTERFACE' or '$WG_NOPROXY_INTERFACE'."
        exit 1
    fi

    server_public_key=$(wg show "$CLIENT_INTERFACE" public-key 2>/dev/null || true)
    if [ -z "$server_public_key" ]; then
        echo "Error: WireGuard interface '$CLIENT_INTERFACE' is not running. Please set up the servers first."
        exit 1
    fi

    if [ "$CLIENT_INTERFACE" == "$WG_PROXY_INTERFACE" ]; then
        port="$WG_PROXY_PORT"
    else
        port="$WG_NOPROXY_PORT"
    fi

    add_client "$CLIENT_INTERFACE" "$CLIENT_NAME" "$server_public_key" "$port"
}

list_clients() {
    echo "Clients for $WG_PROXY_INTERFACE:"
    wg show "$WG_PROXY_INTERFACE" allowed-ips

    echo "Clients for $WG_NOPROXY_INTERFACE:"
    wg show "$WG_NOPROXY_INTERFACE" allowed-ips
}

if ! ip link show "$MAIN_INTERFACE" &>/dev/null; then
    echo "Error: $MAIN_INTERFACE interface does not exist, update the script variables."
    exit 1
fi

if [ -z "${ACTION:-}" ]; then
    while true; do
        echo "WireGuard VPN Setup Script"
        echo "1) Default Setup (Create servers and add Android/iOS clients)"
        echo "2) Setup WireGuard Servers"
        echo "3) Add Client"
        echo "4) List Clients"
        echo "5) Exit"
        read -rp "Choose an option: " choice
        case $choice in
        1)
            default_setup
            ;;
        2)
            setup_servers
            ;;
        3)
            add_client_menu
            ;;
        4)
            list_clients
            ;;
        5)
            print_next_steps
            exit 0
            ;;
        *)
            echo "Invalid option"
            ;;
        esac
        echo -e "\n"
    done
else
    case "$ACTION" in
    default_setup)
        default_setup
        ;;
    setup_servers)
        setup_servers
        ;;
    add_client_cmd)
        add_client_cmd
        ;;
    list_clients)
        list_clients
        ;;
    *)
        echo "Invalid action"
        usage
        ;;
    esac
fi
