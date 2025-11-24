#!/bin/sh

# Configuration parameters
OVPN_PKI="/etc/easy-rsa/pki"
OVPN_DIR="/root/ovpn_config_out"

# Instance management (UCI-aware)
OVPN_INSTANCE="server"        # Current instance being managed (default: "server")
OVPN_INSTANCE_TYPE="server"   # Type: server only (clients not managed by this script)

# Dynamic paths based on instance
OVPN_SERVER_CONF="/etc/openvpn/${OVPN_INSTANCE}.conf"
OVPN_SERVER_BACKUP="/etc/openvpn/${OVPN_INSTANCE}.conf.BAK"

export EASYRSA_PKI="${OVPN_PKI}"
export EASYRSA_BATCH="1"

# OpenVPN server configuration - EDIT THESE VALUES
OVPN_SERV="vpn.example.com"  # Your VPN server address
OVPN_PORT="1194"              # VPN port
OVPN_PROTO="udp"              # Protocol: udp or tcp
OVPN_POOL="10.8.0.0 255.255.255.0"  # VPN subnet

# IPv6 configuration - EDIT THESE VALUES
OVPN_IPV6_ENABLE="no"         # Enable IPv6: yes or no (disabled by default to avoid configuration issues)
OVPN_IPV6_MODE="static"       # Mode: "static" (simple, default) or "dhcpv6" (advanced, tracked)
# IPv6 Pool - Auto-detected from WAN or set manually:
# - For globally routable: Use a /64 from your ISP's delegation
# - For ULA (private): Generate at https://unique-local-ipv6.com/
OVPN_IPV6_POOL="fd42:4242:4242:1194::/64"  # IPv6 VPN subnet
OVPN_IPV6_POOL_SIZE="253"     # Max clients (for tracking/limiting)

# Auto-detect DNS and domain from OpenWrt UCI
OVPN_DNS="${OVPN_POOL%.* *}.1"
OVPN_DOMAIN=$(uci get dhcp.@dnsmasq[0].domain 2>/dev/null || echo "lan")

# Auto-detect IPv6 DNS (first address in IPv6 pool)
OVPN_IPV6_DNS="${OVPN_IPV6_POOL%::*}::1"

# Performance configuration for CPU-limited devices
# Note: Compression is NOT configured due to OpenVPN deprecation and stability issues
# See: https://community.openvpn.net/Pages/Compression
# OVPN_COMPRESSION="no"         # NOT USED - Compression directive omitted from config
OVPN_BANDWIDTH_LIMIT="0"        # Bandwidth limit in bytes/sec (0 = disabled, e.g., 1000000 = ~8 Mbps)

# Function to update dynamic paths when instance changes
update_instance_paths() {
    OVPN_SERVER_CONF="/etc/openvpn/${OVPN_INSTANCE}.conf"
    OVPN_SERVER_BACKUP="/etc/openvpn/${OVPN_INSTANCE}.conf.BAK"
}

# UCI Helper Functions for Instance Management

# Validate instance name (LuCI rules: >3 chars, alphanumeric + underscore)
validate_instance_name() {
    local name="$1"

    if [ -z "$name" ]; then
        return 1
    fi

    # Check length
    if [ ${#name} -le 3 ]; then
        echo "Error: Instance name must be more than 3 characters"
        return 1
    fi

    # Check for valid characters (alphanumeric + underscore)
    if ! echo "$name" | grep -qE '^[a-zA-Z0-9_]+$'; then
        echo "Error: Instance name can only contain letters, numbers, and underscores"
        return 1
    fi

    return 0
}

# List all OpenVPN instances from UCI
list_openvpn_instances() {
    echo ""
    echo "=== OpenVPN Instances (from UCI config) ==="
    echo ""

    # Check if UCI openvpn config exists
    if ! uci show openvpn >/dev/null 2>&1; then
        echo "No UCI OpenVPN configuration found"
        echo "Run this script to auto-create the default 'server' instance"
        return 1
    fi

    local found_instances=0
    local instance_list=""
    local instance_name
    local enabled
    local config_file
    local file_status
    local enabled_status
    local running_status

    # Iterate through UCI sections
    uci show openvpn 2>/dev/null | grep "=openvpn$" | while IFS='=' read -r section_path section_type; do
        # Extract instance name from path (e.g., openvpn.server -> server)
        instance_name=$(echo "$section_path" | cut -d'.' -f2)

        # Get instance details
        enabled=$(uci get openvpn.${instance_name}.enabled 2>/dev/null || echo "0")
        config_file=$(uci get openvpn.${instance_name}.config 2>/dev/null || echo "/etc/openvpn/${instance_name}.conf")

        # Check if it exists as a file
        if [ -f "$config_file" ]; then
            file_status="[exists]"
        else
            file_status="[missing]"
        fi

        # Check if enabled
        if [ "$enabled" = "1" ]; then
            enabled_status="enabled"
        else
            enabled_status="disabled"
        fi

        # Check if running
        if pgrep -f "[o]penvpn.*${instance_name}" >/dev/null 2>&1; then
            running_status="RUNNING"
        else
            running_status="stopped"
        fi

        echo "  Instance: $instance_name"
        echo "    Status: $enabled_status, $running_status"
        echo "    Config: $config_file $file_status"
        echo ""

        found_instances=$((found_instances + 1))
    done

    if [ $found_instances -eq 0 ]; then
        echo "No instances configured"
        echo ""
        return 1
    fi

    return 0
}

# Ensure UCI instance exists (create if missing)
ensure_uci_instance() {
    local instance="$1"
    local current_config
    local expected_config

    if [ -z "$instance" ]; then
        instance="$OVPN_INSTANCE"
    fi

    # Check if instance exists in UCI
    if ! uci get openvpn.${instance} >/dev/null 2>&1; then
        echo "Creating UCI instance: $instance"

        # Create the instance section
        uci set openvpn.${instance}=openvpn
        uci set openvpn.${instance}.enabled=1
        uci set openvpn.${instance}.config="/etc/openvpn/${instance}.conf"
        uci commit openvpn

        echo "UCI instance '$instance' created"
    else
        # Update config path if needed
        current_config=$(uci get openvpn.${instance}.config 2>/dev/null)
        expected_config="/etc/openvpn/${instance}.conf"

        if [ "$current_config" != "$expected_config" ]; then
            uci set openvpn.${instance}.config="$expected_config"
            uci commit openvpn
        fi
    fi

    return 0
}

# Select OpenVPN instance to manage
select_openvpn_instance() {
    echo ""
    echo "=== Select OpenVPN Instance to Manage ==="
    echo ""
    echo "Current instance: $OVPN_INSTANCE"
    echo ""

    # List existing instances
    echo "Available instances:"
    echo ""

    local instance_count=0
    local instances=""
    local inst
    local enabled
    local status
    local choice
    local selected_instance
    local new_instance

    # Get list of instances
    if uci show openvpn >/dev/null 2>&1; then
        instances=$(uci show openvpn 2>/dev/null | grep "=openvpn$" | cut -d'.' -f2 | cut -d'=' -f1)

        for inst in $instances; do
            instance_count=$((instance_count + 1))
            enabled=$(uci get openvpn.${inst}.enabled 2>/dev/null || echo "0")

            if [ "$enabled" = "1" ]; then
                status="enabled"
            else
                status="disabled"
            fi

            if [ "$inst" = "$OVPN_INSTANCE" ]; then
                echo "  $instance_count) $inst ($status) [CURRENT]"
            else
                echo "  $instance_count) $inst ($status)"
            fi
        done
    fi

    echo ""
    echo "  n) Create new instance"
    echo "  c) Cancel"
    echo ""

    if [ $instance_count -eq 0 ]; then
        echo "No instances found. Creating default 'server' instance..."
        OVPN_INSTANCE="server"
        ensure_uci_instance "$OVPN_INSTANCE"
        update_instance_paths
        echo "Default instance 'server' created and selected"
        return 0
    fi

    read -p "Select option: " choice

    case "$choice" in
        [0-9]*)
            # User selected a number
            selected_instance=$(echo "$instances" | sed -n "${choice}p")

            if [ -n "$selected_instance" ]; then
                OVPN_INSTANCE="$selected_instance"
                update_instance_paths
                echo ""
                echo "Selected instance: $OVPN_INSTANCE"
            else
                echo "Invalid selection"
                return 1
            fi
            ;;
        n|N)
            # Create new instance
            echo ""
            read -p "Enter new instance name (>3 chars, alphanumeric + underscore): " new_instance

            if validate_instance_name "$new_instance"; then
                # Check if already exists
                if uci get openvpn.${new_instance} >/dev/null 2>&1; then
                    echo "Error: Instance '$new_instance' already exists"
                    return 1
                fi

                OVPN_INSTANCE="$new_instance"
                ensure_uci_instance "$OVPN_INSTANCE"
                update_instance_paths
                echo ""
                echo "Created and selected instance: $OVPN_INSTANCE"
            else
                return 1
            fi
            ;;
        c|C)
            echo "Cancelled"
            return 1
            ;;
        *)
            echo "Invalid option"
            return 1
            ;;
    esac

    return 0
}

# Function to check and validate DHCPv6 prerequisites
check_dhcpv6_prerequisites() {
    echo ""
    echo "=== DHCPv6 Mode Prerequisites Check ==="
    echo ""

    local all_ok=1

    # Check if odhcpd is installed
    echo "Checking for odhcpd package..."
    if opkg list-installed | grep -q "^odhcpd "; then
        echo "  ✓ odhcpd is installed"
    else
        echo "  ✗ odhcpd is NOT installed"
        echo ""
        echo "    To install: opkg update && opkg install odhcpd"
        all_ok=0
    fi

    echo ""

    # Check if odhcpd is running
    if [ $all_ok -eq 1 ]; then
        echo "Checking if odhcpd is running..."
        if pgrep odhcpd >/dev/null 2>&1; then
            echo "  ✓ odhcpd service is running"
        else
            echo "  ✗ odhcpd service is NOT running"
            echo ""
            echo "    To start: /etc/init.d/odhcpd start"
            echo "    To enable at boot: /etc/init.d/odhcpd enable"
            all_ok=0
        fi
        echo ""
    fi

    # Show configuration requirements
    echo "=== Manual Configuration Required ==="
    echo ""
    echo "DHCPv6 mode requires manual odhcpd configuration:"
    echo ""
    echo "1. Configure odhcpd for VPN interface in /etc/config/dhcp:"
    echo "   config dhcp 'vpn'"
    echo "       option interface 'vpn'"
    echo "       option ra 'server'"
    echo "       option dhcpv6 'server'"
    echo "       option ra_management '1'"
    echo ""
    echo "2. Configure network interface in /etc/config/network:"
    echo "   config interface 'vpn'"
    echo "       option proto 'none'"
    echo "       option ifname 'tun0'"
    echo ""
    echo "3. Restart services:"
    echo "   /etc/init.d/network reload"
    echo "   /etc/init.d/odhcpd restart"
    echo ""
    echo "WARNING: This is an ADVANCED configuration!"
    echo "For most users, STATIC mode is simpler and recommended."
    echo ""

    if [ $all_ok -eq 1 ]; then
        echo "Prerequisites: OK (but manual configuration still needed)"
        return 0
    else
        echo "Prerequisites: FAILED (install/start odhcpd first)"
        return 1
    fi
}

# Function to check if IPv6 subnet conflicts with LAN
check_ipv6_subnet_conflict() {
    local vpn_subnet="$1"

    # Get LAN IPv6 prefix
    local lan_ipv6=$(ip -6 addr show dev br-lan 2>/dev/null | grep "inet6" | grep -v "fe80::" | grep -v "::1" | head -1)

    if [ -z "$lan_ipv6" ]; then
        # No LAN IPv6, no conflict possible
        return 0
    fi

    # Extract LAN prefix (simplified comparison)
    local lan_prefix=$(echo "$lan_ipv6" | awk '{print $2}' | cut -d'/' -f1 | sed 's/::[0-9a-f]*$//')
    local vpn_prefix=$(echo "$vpn_subnet" | sed 's/::[0-9a-f]*$//' | sed 's/\/[0-9]*$//')

    # Simple prefix comparison (first 64 bits)
    if [ "$lan_prefix" = "$vpn_prefix" ]; then
        echo ""
        echo "WARNING: VPN subnet conflicts with LAN IPv6 subnet!"
        echo "  LAN is using: ${lan_prefix}/64"
        echo "  VPN subnet:   $vpn_subnet"
        echo ""
        echo "This will cause routing problems. Use a different /64 subnet for VPN."
        echo ""
        return 1
    fi

    return 0
}

# Function to detect IPv6 prefix delegation from WAN
detect_ipv6_prefix() {
    local WAN6_IF
    local wan6_addrs
    local prefix_delegation
    local prefix_size
    local lan_ipv6
    local lan_prefix

    echo "Detecting IPv6 configuration from WAN interface..."
    echo ""

    # Get WAN interface name
    . /lib/functions/network.sh
    network_flush_cache
    network_find_wan6 WAN6_IF

    if [ -z "$WAN6_IF" ]; then
        echo "  No WAN IPv6 interface found"
        echo "  IPv6 may not be configured on this router"
        return 1
    fi

    echo "  WAN IPv6 interface: $WAN6_IF"

    # Get IPv6 addresses and prefixes
    wan6_addrs=$(ip -6 addr show dev "$WAN6_IF" 2>/dev/null | grep "inet6" | grep -v "fe80::" | grep -v "::1")

    if [ -z "$wan6_addrs" ]; then
        echo "  No global IPv6 addresses found on WAN"
        echo "  Check your ISP's IPv6 connectivity"
        return 1
    fi

    echo "  IPv6 addresses on WAN:"
    echo "$wan6_addrs" | while read line; do
        echo "    $line"
    done
    echo ""

    # Try to detect prefix delegation size
    prefix_delegation=$(uci get network.wan6.ip6prefix 2>/dev/null)
    if [ -n "$prefix_delegation" ]; then
        echo "  Detected IPv6 prefix delegation: $prefix_delegation"

        # Extract prefix size (e.g., /56, /64)
        prefix_size=$(echo "$prefix_delegation" | grep -o '/[0-9]*' | tr -d '/')

        if [ "$prefix_size" -le 60 ]; then
            echo "  You have multiple /64 subnets available!"
            echo "  Recommended: Dedicate one /64 subnet for OpenVPN clients"
        elif [ "$prefix_size" -eq 64 ]; then
            echo "  You have a single /64 subnet"
            echo "  Warning: Sharing a /64 between LAN and VPN requires NDP proxy"
        else
            echo "  Prefix is smaller than /64 - IPv6 may not work correctly"
        fi
    else
        echo "  No prefix delegation detected in UCI config"
        echo "  IPv6 may be using SLAAC only"
    fi

    echo ""

    # Check LAN IPv6 configuration
    echo "Checking LAN IPv6 configuration..."
    lan_ipv6=$(ip -6 addr show dev br-lan 2>/dev/null | grep "inet6" | grep -v "fe80::" | grep -v "::1" | head -1)

    if [ -n "$lan_ipv6" ]; then
        echo "  LAN IPv6 addresses found:"
        echo "    $lan_ipv6"

        # Extract LAN IPv6 prefix
        lan_prefix=$(echo "$lan_ipv6" | awk '{print $2}' | cut -d'/' -f1 | sed 's/::[0-9a-f]*$/::/')
        echo "  LAN IPv6 prefix: ${lan_prefix}/64"
        echo ""
        echo "  IMPORTANT: Use a DIFFERENT /64 subnet for VPN to avoid conflicts"
        echo "  Do NOT use ${lan_prefix}/64 for your VPN pool"
    else
        echo "  No global IPv6 addresses on LAN interface"
        echo "  WARNING: IPv6 may not be properly configured on your router"
        echo ""
        echo "  Common causes:"
        echo "    - No IPv6 prefix delegation from ISP"
        echo "    - DHCPv6 not configured on LAN"
        echo "    - IPv6 disabled on LAN interface"
        echo ""
        echo "  To check DHCPv6 logs: logread | grep -i 'dhcp.*no addresses available'"
    fi

    echo ""
    return 0
}

# Auto-Detect DDNS configured name, Fetch server address configured elsewhere
auto_detect_fqdn() {
    local DETECTED_PORT
    local DETECTED_PROTO
    local DETECTED_POOL
    local DETECTED_IPV6_POOL
    local rule_index
    local rule_name
    local rule_dest_port
    local rule_proto
    local NET_FQDN
    local NET_IF
    local NET_ADDR

    echo ""
    echo "Script default settings (if no config found):"
    echo "  Port: $OVPN_PORT"
    echo "  Protocol: $OVPN_PROTO"
    echo "  IPv4 VPN Subnet: $OVPN_POOL"
    echo "  IPv4 DNS Server: $OVPN_DNS"
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "  IPv6: ENABLED (will be configured)"
        echo "    IPv6 VPN Subnet: $OVPN_IPV6_POOL"
        echo "    IPv6 DNS Server: $OVPN_IPV6_DNS"
    else
        echo "  IPv6: DISABLED (will not be configured)"
    fi
    echo "  Domain: $OVPN_DOMAIN"
    echo "  VPN Server: $OVPN_SERV"
    echo ""

    echo "Detecting configuration from system..."
    echo ""

    # Try to detect from existing server.conf first
    if [ -f "$OVPN_SERVER_CONF" ]; then
        echo "Found existing server.conf, reading settings..."

        # Detect port
        DETECTED_PORT=$(grep "^port " "$OVPN_SERVER_CONF" | awk '{print $2}')
        if [ -n "$DETECTED_PORT" ]; then
            OVPN_PORT="$DETECTED_PORT"
            echo "  Detected port: $OVPN_PORT"
        fi

        # Detect protocol
        DETECTED_PROTO=$(grep "^proto " "$OVPN_SERVER_CONF" | awk '{print $2}')
        if [ -n "$DETECTED_PROTO" ]; then
            OVPN_PROTO="$DETECTED_PROTO"
            echo "  Detected protocol: $OVPN_PROTO"
        fi

        # Detect server pool (format: "server 10.8.0.0 255.255.255.0")
        DETECTED_POOL=$(grep "^server " "$OVPN_SERVER_CONF" | grep -v "server-ipv6" | awk '{print $2, $3}')
        if [ -n "$DETECTED_POOL" ]; then
            OVPN_POOL="$DETECTED_POOL"
            echo "  Detected IPv4 VPN subnet: $OVPN_POOL"
        fi

        # Detect IPv6 pool (format: "server-ipv6 fd42:4242:4242:1194::/64")
        DETECTED_IPV6_POOL=$(grep "^server-ipv6 " "$OVPN_SERVER_CONF" | awk '{print $2}')
        if [ -n "$DETECTED_IPV6_POOL" ]; then
            OVPN_IPV6_POOL="$DETECTED_IPV6_POOL"
            OVPN_IPV6_ENABLE="yes"
            OVPN_IPV6_DNS="${OVPN_IPV6_POOL%::*}::1"
            echo "  Detected IPv6 VPN subnet: $OVPN_IPV6_POOL"
            echo "  IPv6 is CURRENTLY CONFIGURED and active"
        else
            # Check if IPv6 is explicitly disabled
            if grep -q "^#.*server-ipv6" "$OVPN_SERVER_CONF"; then
                OVPN_IPV6_ENABLE="no"
                echo "  IPv6 is commented out (disabled) in server.conf"
            else
                echo "  IPv6 is NOT configured in server.conf"
                if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
                    echo "  (Script default is enabled - use option 1 to add IPv6)"
                else
                    echo "  (Script default is disabled - use option 3 to enable)"
                fi
            fi
        fi

        echo ""
    fi

    # If port/proto not found in server.conf, try firewall rules
    if [ -z "$DETECTED_PORT" ] || [ -z "$DETECTED_PROTO" ]; then
        echo "Checking firewall rules for OpenVPN configuration..."

        rule_index=0
        while true; do
            rule_name=$(uci get "firewall.@rule[${rule_index}].name" 2>/dev/null)
            if [ $? -ne 0 ]; then
                break
            fi

            # Look for OpenVPN-related rules
            if echo "$rule_name" | grep -qi "openvpn\|vpn"; then
                rule_dest_port=$(uci get "firewall.@rule[${rule_index}].dest_port" 2>/dev/null)
                rule_proto=$(uci get "firewall.@rule[${rule_index}].proto" 2>/dev/null)

                if [ -n "$rule_dest_port" ] && [ -z "$DETECTED_PORT" ]; then
                    OVPN_PORT="$rule_dest_port"
                    echo "  Detected port from firewall: $OVPN_PORT"
                fi

                if [ -n "$rule_proto" ] && [ "$rule_proto" != "tcpudp" ] && [ -z "$DETECTED_PROTO" ]; then
                    OVPN_PROTO="$rule_proto"
                    echo "  Detected protocol from firewall: $OVPN_PROTO"
                fi
            fi

            rule_index=$((rule_index + 1))
        done
        echo ""
    fi

    # Update DNS based on detected pool
    OVPN_DNS="${OVPN_POOL%.* *}.1"

    # Detect server FQDN/IP
    NET_FQDN="$(uci -q get ddns.@service[0].lookup_host)"
    . /lib/functions/network.sh
    network_flush_cache
    network_find_wan NET_IF
    network_get_ipaddr NET_ADDR "${NET_IF}"
    if [ -n "${NET_FQDN}" ]
    then
        OVPN_SERV="${NET_FQDN}"
        echo "Detected DDNS hostname: $OVPN_SERV"
    else
        OVPN_SERV="${NET_ADDR}"
        echo "Detected WAN IP address: $OVPN_SERV"
    fi

    echo ""
    echo "=== IPv6 Prefix Detection ==="
    echo ""
    detect_ipv6_prefix

    echo ""
    echo "=== Final Settings (will be used for new configs) ==="
    echo ""
    echo "Network Configuration:"
    echo "  Port: $OVPN_PORT"
    echo "  Protocol: $OVPN_PROTO"
    echo "  VPN Server Address: $OVPN_SERV"
    echo ""
    echo "IPv4 Configuration:"
    echo "  VPN Subnet: $OVPN_POOL"
    echo "  DNS Server: $OVPN_DNS"
    echo "  Domain: $OVPN_DOMAIN"
    echo ""
    echo "IPv6 Configuration:"
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "  Status: ENABLED - will be included in server.conf"
        echo "  Mode: $OVPN_IPV6_MODE (static=simple, dhcpv6=advanced/tracked)"
        echo "  VPN Subnet: $OVPN_IPV6_POOL"
        echo "  DNS Server: $OVPN_IPV6_DNS"
        echo "  Max Clients: $OVPN_IPV6_POOL_SIZE"
    else
        echo "  Status: DISABLED - will NOT be included in server.conf"
        echo "  (Use option 3 to enable IPv6 support)"
    fi
    echo ""

}

# Ensure output directory exists
if [ ! -d "$OVPN_DIR" ]; then
    mkdir -p "$OVPN_DIR"
fi

# Ensure default UCI instance exists on first run
if ! uci show openvpn >/dev/null 2>&1 || ! uci get openvpn.${OVPN_INSTANCE} >/dev/null 2>&1; then
    echo "Initializing default OpenVPN instance: $OVPN_INSTANCE"
    ensure_uci_instance "$OVPN_INSTANCE"
    echo ""
fi

# Function to configure VPN firewall zones
configure_vpn_firewall() {
    local confirm
    local ipv6_forward
    local lan_ipv6
    local wan_ipv6
    local lan_forward
    local restart_net
    local restart

    echo ""
    echo "=== Configure VPN Firewall Access ==="
    echo ""
    echo "This will configure the firewall to:"
    echo "  1. Add VPN interface (tun+) to LAN zone (trusted)"
    echo "  2. Allow OpenVPN port ${OVPN_PORT}/${OVPN_PROTO} from WAN (IPv4 & IPv6)"
    echo "  3. Give VPN clients same access as LAN devices"
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "  4. Enable IPv6 forwarding for VPN"
    fi
    echo ""

    # Check if firewall config exists
    if ! uci show firewall >/dev/null 2>&1; then
        echo "ERROR: Cannot access firewall configuration"
        return 1
    fi

    read -p "Continue with firewall configuration? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        echo "Operation cancelled."
        return 0
    fi

    echo ""
    echo "Configuring firewall..."

    # Create UCI network interface for VPN (makes it visible in LuCI)
    echo "  Creating VPN network interface in UCI..."

    # Verify network UCI config exists
    if ! uci show network >/dev/null 2>&1; then
        echo "    ERROR: Network UCI configuration not found"
        echo "    Your OpenWrt installation may be incomplete"
        echo "    Cannot create VPN interface in UCI"
        echo ""
        return 1
    fi

    # Check if vpn interface already exists
    if ! uci get network.vpn >/dev/null 2>&1; then
        if uci set network.vpn=interface && \
           uci set network.vpn.proto='none' && \
           uci set network.vpn.device='tun+' && \
           uci set network.vpn.auto='1'; then
            if uci commit network; then
                echo "    Created 'vpn' network interface (will show in LuCI Network → Interfaces)"
            else
                echo "    ERROR: Failed to commit network configuration"
                return 1
            fi
        else
            echo "    ERROR: Failed to create VPN network interface"
            echo "    UCI network configuration may be read-only or corrupted"
            return 1
        fi
    else
        echo "    VPN network interface already exists"
    fi

    # Rename zones for easier reference (if not already named)
    uci rename firewall.@zone[0]="lan" 2>/dev/null
    uci rename firewall.@zone[1]="wan" 2>/dev/null

    # Verify LAN zone exists before configuring
    if ! uci get firewall.lan >/dev/null 2>&1; then
        echo "  ERROR: LAN firewall zone not found"
        echo "  Your firewall configuration may not be initialized"
        echo "  Please configure firewall through LuCI first, then run this script"
        echo ""
        uci commit firewall 2>/dev/null
        return 1
    fi

    # Remove tun+ from LAN zone if it exists, then add it fresh
    uci del_list firewall.lan.device="tun+" 2>/dev/null
    uci add_list firewall.lan.device="tun+" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo "  Added tun+ interface to LAN zone"
    else
        echo "  WARNING: Could not add tun+ to LAN zone"
        echo "  You may need to configure firewall manually"
    fi

    # Verify WAN zone exists before creating rules
    if ! uci get firewall.wan >/dev/null 2>&1; then
        echo "  ERROR: WAN firewall zone not found"
        echo "  Cannot create OpenVPN firewall rule without WAN zone"
        echo "  Please ensure firewall is properly configured in LuCI"
        echo ""
        uci commit firewall
        return 1
    fi

    # Delete existing OpenVPN rule if present, then create fresh
    uci -q delete firewall.ovpn

    # Create new OpenVPN firewall rule
    if ! uci set firewall.ovpn="rule"; then
        echo "  ERROR: Failed to create OpenVPN firewall rule"
        echo "  UCI firewall configuration may be corrupted"
        return 1
    fi

    uci set firewall.ovpn.name="Allow-OpenVPN"
    uci set firewall.ovpn.src="wan"
    uci set firewall.ovpn.dest_port="${OVPN_PORT}"
    uci set firewall.ovpn.proto="${OVPN_PROTO}"
    uci set firewall.ovpn.target="ACCEPT"
    uci set firewall.ovpn.family="any"

    echo "  Created OpenVPN WAN access rule (IPv4 & IPv6)"

    # Configure IPv6 firewall rules if IPv6 is enabled
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "  Configuring IPv6 firewall rules..."

        # Enable IPv6 forwarding at kernel level
        ipv6_forward=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "0")
        if [ "$ipv6_forward" != "1" ]; then
            echo "    Enabling IPv6 forwarding..."
            sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

            # Make it persistent
            if ! grep -q "net.ipv6.conf.all.forwarding" /etc/sysctl.conf 2>/dev/null; then
                echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
                echo "    IPv6 forwarding enabled (persistent)"
            fi
        else
            echo "    IPv6 forwarding already enabled"
        fi

        # Enable IPv6 on LAN zone
        lan_ipv6=$(uci get firewall.lan.ipv6 2>/dev/null)
        if [ "$lan_ipv6" != "1" ]; then
            if uci set firewall.lan.ipv6='1'; then
                echo "    Enabled IPv6 on LAN zone"
            else
                echo "    ERROR: Failed to enable IPv6 on LAN zone"
            fi
        fi

        # Enable IPv6 on WAN zone
        wan_ipv6=$(uci get firewall.wan.ipv6 2>/dev/null)
        if [ "$wan_ipv6" != "1" ]; then
            if uci set firewall.wan.ipv6='1'; then
                echo "    Enabled IPv6 on WAN zone"
            else
                echo "    ERROR: Failed to enable IPv6 on WAN zone"
            fi
        fi

        # Ensure LAN zone allows IPv6 forwarding
        lan_forward=$(uci get firewall.lan.forward 2>/dev/null)
        if [ "$lan_forward" != "ACCEPT" ]; then
            if uci set firewall.lan.forward='ACCEPT'; then
                echo "    Enabled IPv6 forwarding on LAN zone"
            else
                echo "    ERROR: Failed to enable forwarding on LAN zone"
            fi
        fi

        # Create specific IPv6 forwarding rule from VPN to WAN
        uci -q delete firewall.vpn_ipv6_forward

        if uci set firewall.vpn_ipv6_forward="forwarding"; then
            uci set firewall.vpn_ipv6_forward.src="lan"
            uci set firewall.vpn_ipv6_forward.dest="wan"
            uci set firewall.vpn_ipv6_forward.family="ipv6"
            echo "    Created IPv6 forwarding rule (VPN → WAN)"
        else
            echo "    ERROR: Failed to create IPv6 forwarding rule"
            echo "    IPv6 routing may not work correctly"
        fi

        echo "  IPv6 firewall configuration complete"
    fi

    # Commit changes
    uci commit firewall

    echo ""
    echo "Firewall configuration updated"
    echo ""

    # Restart network to register VPN interface
    echo "To make VPN interface visible in LuCI, network service needs restart."
    read -p "Restart network service? (y/n): " restart_net
    if [ "$restart_net" = "y" ] || [ "$restart_net" = "Y" ]; then
        /etc/init.d/network restart
        echo "Network service restarted"
        sleep 2
    fi

    echo ""
    read -p "Restart firewall to apply changes? (y/n): " restart
    if [ "$restart" = "y" ] || [ "$restart" = "Y" ]; then
        /etc/init.d/firewall restart
        echo "Firewall restarted"
        echo ""
        echo "VPN clients will now have full LAN access"
        if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
            echo "IPv6 routing enabled for VPN clients"
        fi
        echo ""
        echo "VPN interface will appear in LuCI Network → Interfaces as 'vpn'"
        echo "Note: It will show as 'down' until OpenVPN is running"
    else
        echo "Remember to restart services:"
        echo "  Network: /etc/init.d/network restart"
        echo "  Firewall: /etc/init.d/firewall restart"
    fi

    echo ""
}

# Function to diagnose IPv6 routing issues
diagnose_ipv6_routing() {
    echo ""
    echo "=== IPv6 Routing Diagnostic ==="
    echo ""

    local issues_found=0

    # Check 1: IPv6 forwarding enabled
    echo "1. Checking IPv6 forwarding..."
    local ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)
    if [ "$ipv6_forward" = "1" ]; then
        echo "   [OK] IPv6 forwarding is enabled"
    else
        echo "   [FAIL] IPv6 forwarding is DISABLED"
        echo "   Fix: sysctl -w net.ipv6.conf.all.forwarding=1"
        issues_found=$((issues_found + 1))
    fi
    echo ""

    # Check 2: Router has IPv6 WAN connectivity
    echo "2. Checking router IPv6 WAN connectivity..."
    local wan6_addr=$(ip -6 addr show | grep "scope global" | grep -v "fd00:" | grep -v "fe80:" | head -1)
    if [ -n "$wan6_addr" ]; then
        echo "   [OK] Router has global IPv6 address"
        echo "   $wan6_addr"
    else
        echo "   [FAIL] Router has NO global IPv6 address"
        echo "   Your router needs IPv6 connectivity from ISP first"
        issues_found=$((issues_found + 1))
    fi
    echo ""

    # Check 3: Default IPv6 route exists
    echo "3. Checking IPv6 default route..."
    if ip -6 route show default | grep -q "default"; then
        echo "   [OK] IPv6 default route exists"
        ip -6 route show default | sed 's/^/   /'
    else
        echo "   [FAIL] No IPv6 default route found"
        echo "   Router cannot route IPv6 traffic to internet"
        issues_found=$((issues_found + 1))
    fi
    echo ""

    # Check 4: VPN tunnel has IPv6 address
    echo "4. Checking VPN tunnel IPv6 configuration..."
    if ip -6 addr show dev tun0 2>/dev/null | grep -q "inet6"; then
        echo "   [OK] VPN tunnel has IPv6 address"
        ip -6 addr show dev tun0 | grep "inet6" | sed 's/^/   /'
    else
        echo "   [FAIL] VPN tunnel (tun0) has no IPv6 address"
        echo "   Check: Is IPv6 enabled in server.conf?"
        echo "   Check: Is OpenVPN running?"
        issues_found=$((issues_found + 1))
    fi
    echo ""

    # Check 5: IPv6 route for VPN subnet
    echo "5. Checking IPv6 routes for VPN subnet..."
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        local vpn_prefix=$(echo "$OVPN_IPV6_POOL" | cut -d'/' -f1 | sed 's/::[0-9a-f:]*$//')
        if ip -6 route show | grep -q "$vpn_prefix"; then
            echo "   [OK] Route exists for VPN IPv6 subnet"
            ip -6 route show | grep "$vpn_prefix" | sed 's/^/   /'
        else
            echo "   [WARN] No specific route for VPN subnet $OVPN_IPV6_POOL"
            echo "   This might be OK if using connected route"
        fi
    else
        echo "   [SKIP] IPv6 is disabled in configuration"
    fi
    echo ""

    # Check 6: Firewall IPv6 forwarding
    echo "6. Checking firewall IPv6 forwarding rules..."
    if uci show firewall | grep -q "ipv6.*1"; then
        echo "   [OK] IPv6 firewall rules exist"
    else
        echo "   [WARN] No IPv6 firewall rules found"
        echo "   You may need to enable IPv6 in firewall zones"
    fi
    echo ""

    # Check 7: NAT/Masquerading (should NOT be needed for IPv6)
    echo "7. Checking for IPv6 NAT (should NOT be present)..."
    if ip6tables -t nat -L -n 2>/dev/null | grep -q "MASQUERADE\|SNAT"; then
        echo "   [WARN] IPv6 NAT detected - this is unusual"
        echo "   IPv6 should use direct routing, not NAT"
        issues_found=$((issues_found + 1))
    else
        echo "   [OK] No IPv6 NAT (correct configuration)"
    fi
    echo ""

    # Check 8: Test IPv6 connectivity from router
    echo "8. Testing IPv6 connectivity from router..."
    if ping6 -c 1 -W 2 2001:4860:4860::8888 >/dev/null 2>&1; then
        echo "   [OK] Router can ping IPv6 internet (Google DNS)"
    else
        echo "   [FAIL] Router cannot ping IPv6 internet"
        echo "   Check: ISP IPv6 connectivity"
        echo "   Check: Firewall rules"
        issues_found=$((issues_found + 1))
    fi
    echo ""

    # Summary
    echo "=========================================="
    if [ $issues_found -eq 0 ]; then
        echo "RESULT: No critical issues found"
        echo ""
        echo "If clients still can't access IPv6:"
        echo "  1. Check client-side: Does client have IPv6 address from VPN?"
        echo "  2. Check client routes: ip -6 route (on client)"
        echo "  3. Check server logs: logread | grep openvpn"
        echo "  4. Verify server.conf has correct IPv6 directives"
    else
        echo "RESULT: Found $issues_found critical issue(s)"
        echo ""
        echo "Fix the issues above, then:"
        echo "  1. Restart networking: /etc/init.d/network restart"
        echo "  2. Restart firewall: /etc/init.d/firewall restart"
        echo "  3. Restart OpenVPN: /etc/init.d/openvpn restart"
    fi
    echo "=========================================="
    echo ""
}

# Function to check if OpenVPN port is open in firewall and VPN zone configuration
check_firewall() {
    local vpn_in_lan
    local lan_devices
    local port_open
    local rule_index
    local rule_name
    local rule_src
    local rule_proto
    local rule_dest_port
    local rule_target
    local ipv6_issues
    local ipv6_forward
    local lan_ipv6
    local wan_ipv6
    local lan_forward

    echo ""
    echo "=== Checking Firewall Configuration ==="
    echo ""

    # Check if firewall config exists
    if ! uci show firewall >/dev/null 2>&1; then
        echo "WARNING: Cannot access firewall configuration"
        echo "Firewall may not be configured or UCI is not available"
        return 1
    fi

    # Check 1: VPN interface in LAN zone
    echo "1. Checking VPN interface configuration..."
    echo ""

    vpn_in_lan=0
    lan_devices=$(uci get firewall.@zone[0].device 2>/dev/null)

    # Check if tun+ is in the device list
    echo "$lan_devices" | grep -q "tun+" && vpn_in_lan=1

    if [ $vpn_in_lan -eq 1 ]; then
        echo "   [OK] VPN interface (tun+) is in LAN zone"
        echo "        VPN clients have full LAN access"
    else
        echo "   [MISSING] VPN interface (tun+) is NOT in LAN zone"
        echo "        VPN clients may have limited access"
        echo ""
        echo "   To add VPN interface to LAN zone, use option 15"
    fi

    # Check if UCI network interface exists for LuCI visibility
    if uci get network.vpn >/dev/null 2>&1; then
        echo "   [OK] VPN network interface exists in UCI"
        echo "        Will appear in LuCI Network → Interfaces as 'vpn'"
    else
        echo "   [INFO] VPN network interface not in UCI"
        echo "        Won't appear in LuCI interface list"
        echo "        Run option 15 to create it"
    fi

    echo ""
    
    # Check 2: OpenVPN port open from WAN
    echo "2. Checking OpenVPN port ${OVPN_PORT}/${OVPN_PROTO} on WAN..."
    echo ""
    
    port_open=0
    rule_index=0
    
    # Loop through all firewall rules
    while true; do
        rule_name=$(uci get "firewall.@rule[${rule_index}].name" 2>/dev/null)
        if [ $? -ne 0 ]; then
            # No more rules
            break
        fi
        
        # Get rule properties
        rule_src=$(uci get "firewall.@rule[${rule_index}].src" 2>/dev/null)
        rule_proto=$(uci get "firewall.@rule[${rule_index}].proto" 2>/dev/null)
        rule_dest_port=$(uci get "firewall.@rule[${rule_index}].dest_port" 2>/dev/null)
        rule_target=$(uci get "firewall.@rule[${rule_index}].target" 2>/dev/null)
        
        # Check if this rule opens our OpenVPN port
        if [ "$rule_src" = "wan" ] && \
           [ "$rule_target" = "ACCEPT" ] && \
           [ "$rule_dest_port" = "$OVPN_PORT" ]; then
            
            # Check if protocol matches (or if rule accepts all protocols)
            if [ "$rule_proto" = "$OVPN_PROTO" ] || \
               [ "$rule_proto" = "tcpudp" ] || \
               [ -z "$rule_proto" ]; then
                port_open=1
                echo "   [OK] Firewall rule found: $rule_name"
                echo "        Port ${OVPN_PORT}/${OVPN_PROTO} is OPEN on WAN"
                break
            fi
        fi
        
        rule_index=$((rule_index + 1))
    done
    
    if [ $port_open -eq 0 ]; then
        echo "   [MISSING] No firewall rule found!"
        echo ""
        echo "   OpenVPN port ${OVPN_PORT}/${OVPN_PROTO} does not appear to be open on WAN."
        echo ""
        echo "   To configure firewall properly, use option 14"
    fi
    
    echo ""

    # Check 3: IPv6 firewall configuration (if IPv6 is enabled)
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "3. Checking IPv6 firewall configuration..."
        echo ""

        ipv6_issues=0

        # Check IPv6 forwarding at kernel level
        ipv6_forward=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "0")
        if [ "$ipv6_forward" = "1" ]; then
            echo "   [OK] IPv6 forwarding enabled at kernel level"
        else
            echo "   [MISSING] IPv6 forwarding DISABLED at kernel level"
            echo "        Run: sysctl -w net.ipv6.conf.all.forwarding=1"
            ipv6_issues=$((ipv6_issues + 1))
        fi

        # Check LAN zone IPv6
        lan_ipv6=$(uci get firewall.lan.ipv6 2>/dev/null)
        if [ "$lan_ipv6" = "1" ]; then
            echo "   [OK] IPv6 enabled on LAN zone"
        else
            echo "   [MISSING] IPv6 NOT enabled on LAN zone"
            ipv6_issues=$((ipv6_issues + 1))
        fi

        # Check WAN zone IPv6
        wan_ipv6=$(uci get firewall.wan.ipv6 2>/dev/null)
        if [ "$wan_ipv6" = "1" ]; then
            echo "   [OK] IPv6 enabled on WAN zone"
        else
            echo "   [MISSING] IPv6 NOT enabled on WAN zone"
            ipv6_issues=$((ipv6_issues + 1))
        fi

        # Check LAN zone forwarding
        lan_forward=$(uci get firewall.lan.forward 2>/dev/null)
        if [ "$lan_forward" = "ACCEPT" ]; then
            echo "   [OK] LAN zone allows forwarding"
        else
            echo "   [WARN] LAN zone forwarding: $lan_forward (should be ACCEPT)"
        fi

        # Check IPv6 forwarding rule
        if uci get firewall.vpn_ipv6_forward >/dev/null 2>&1; then
            echo "   [OK] IPv6 forwarding rule exists (VPN → WAN)"
        else
            echo "   [MISSING] IPv6 forwarding rule NOT configured"
            ipv6_issues=$((ipv6_issues + 1))
        fi

        if [ $ipv6_issues -gt 0 ]; then
            echo ""
            echo "   To fix IPv6 firewall issues, use option 15"
        fi

        echo ""
    fi

    echo "=== Summary ==="
    echo ""

    if [ $vpn_in_lan -eq 1 ] && [ $port_open -eq 1 ]; then
        if [ "$OVPN_IPV6_ENABLE" = "yes" ] && [ $ipv6_issues -gt 0 ]; then
            echo "  IPv4 firewall is properly configured"
            echo "  IPv6 firewall has $ipv6_issues issue(s)"
            echo "  Use option 15 to configure IPv6 firewall"
        else
            echo "  Firewall is properly configured for OpenVPN"
            if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
                echo "  IPv6 firewall rules are correct"
            fi
        fi
    else
        echo "  Firewall configuration incomplete"
        echo "  Use option 15 to automatically configure firewall"
    fi

    echo ""
}

# Function to generate/update server.conf
generate_server_conf() {
    local OVPN_IPV6_SERVER
    local OVPN_IPV6_CLIENT
    local OVPN_BW_MBPS
    local confirm
    local continue_static
    local view
    local restart

    echo ""
    echo "=== Generate/Update OpenVPN Server Configuration ==="
    echo ""
    echo "Configuration to be generated:"
    echo ""
    echo "Network Settings:"
    echo "  Port: $OVPN_PORT"
    echo "  Protocol: $OVPN_PROTO"
    echo ""
    echo "IPv4 Settings (will be included):"
    echo "  VPN Subnet: $OVPN_POOL"
    echo "  DNS Server: $OVPN_DNS"
    echo "  Domain: $OVPN_DOMAIN"
    echo ""
    echo "IPv6 Settings:"
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        OVPN_IPV6_SERVER="${OVPN_IPV6_POOL%::*}::1"
        OVPN_IPV6_CLIENT="${OVPN_IPV6_POOL%::*}::2"
        echo "  Status: ENABLED - IPv6 will be configured"
        echo "  VPN Subnet: $OVPN_IPV6_POOL"
        echo "  Server Address: $OVPN_IPV6_SERVER"
        echo "  Client Address: $OVPN_IPV6_CLIENT"
        echo "  DNS Server: $OVPN_IPV6_DNS"
        echo "  Routes: All IPv6 traffic (2000::/3) via VPN"
    else
        echo "  Status: DISABLED - IPv6 will NOT be configured"
        echo "  (Use option 3 to enable IPv6 before generating config)"
    fi
    echo ""
    echo "Performance Settings:"
    echo "  Compression: Not configured (deprecated - see OpenVPN community docs)"
    if [ "$OVPN_BANDWIDTH_LIMIT" -gt 0 ] 2>/dev/null; then
        OVPN_BW_MBPS=$(awk "BEGIN {printf \"%.2f\", ($OVPN_BANDWIDTH_LIMIT * 8) / 1000000}")
        echo "  Bandwidth Limit: $OVPN_BANDWIDTH_LIMIT bytes/sec (~${OVPN_BW_MBPS} Mbps)"
    else
        echo "  Bandwidth Limit: DISABLED (unlimited)"
    fi
    echo ""

    # Warning about IPv6 leak if IPv6 is disabled
    if [ "$OVPN_IPV6_ENABLE" != "yes" ]; then
        echo "=========================================="
        echo "WARNING: IPv6 TRAFFIC LEAK RISK"
        echo "=========================================="
        echo ""
        echo "IPv6 is DISABLED on this VPN server."
        echo ""
        echo "IMPORTANT: VPN clients with IPv6 connectivity will send IPv6 traffic"
        echo "OUTSIDE the VPN tunnel through their local connection."
        echo ""
        echo "This means:"
        echo "  - IPv6 traffic will NOT be protected by the VPN"
        echo "  - Client's real IPv6 address will be exposed"
        echo "  - Privacy/security may be compromised"
        echo ""
        echo "Solutions:"
        echo "  1. Enable IPv6 on VPN (Menu Option 3) - Recommended if you have IPv6"
        echo "  2. Disable IPv6 on client devices"
        echo "  3. Use client-side firewall to block IPv6"
        echo ""
        echo "If you don't have IPv6 connectivity or don't need it, you can ignore this."
        echo "=========================================="
        echo ""
        read -p "Press Enter to continue..."
        echo ""
    fi

    if [ -f "$OVPN_SERVER_CONF" ]; then
        echo "WARNING: Existing server.conf found at $OVPN_SERVER_CONF"
        echo "A backup will be created at $OVPN_SERVER_BACKUP"
        echo ""
        read -p "Continue and overwrite? (yes/no): " confirm
        
        if [ "$confirm" != "yes" ]; then
            echo "Operation cancelled."
            return 0
        fi
        
        # Create backup
        echo "Creating backup..."
        cp "$OVPN_SERVER_CONF" "$OVPN_SERVER_BACKUP"
        echo "Backup created: $OVPN_SERVER_BACKUP"
    else
        echo "No existing server.conf found. Creating new configuration."
        read -p "Continue? (y/n): " confirm
        
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            echo "Operation cancelled."
            return 0
        fi
    fi
    
    echo ""
    echo "Generating server.conf..."
    
    # Ensure directory exists
    mkdir -p "$(dirname "$OVPN_SERVER_CONF")"
    
    # Generate server configuration
    cat << EOF > ${OVPN_SERVER_CONF}
# OpenVPN Server Configuration
# Generated by openvpn_server_management.sh

# Network settings
port ${OVPN_PORT}
proto ${OVPN_PROTO}
dev tun

# Server mode and VPN subnet (IPv4)
server ${OVPN_POOL}
topology subnet

EOF

    # Add IPv6 configuration if enabled
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        # Warn if DHCPv6 mode is selected (not fully automated yet)
        if [ "$OVPN_IPV6_MODE" = "dhcpv6" ]; then
            echo ""
            echo "WARNING: DHCPv6 mode selected but configuration is STATIC"
            echo "The script will generate a static IPv6 configuration."
            echo "You must manually configure odhcpd for DHCPv6 lease tracking."
            echo ""
            read -p "Continue with static IPv6 configuration? (y/n): " continue_static
            if [ "$continue_static" != "y" ] && [ "$continue_static" != "Y" ]; then
                echo "Configuration generation cancelled."
                return 1
            fi
        fi

        # Calculate IPv6 server and client addresses for ifconfig-ipv6
        OVPN_IPV6_SERVER="${OVPN_IPV6_POOL%::*}::1"
        OVPN_IPV6_CLIENT="${OVPN_IPV6_POOL%::*}::2"

        cat << EOF >> ${OVPN_SERVER_CONF}
# IPv6 configuration
server-ipv6 ${OVPN_IPV6_POOL}
ifconfig-ipv6 ${OVPN_IPV6_SERVER} ${OVPN_IPV6_CLIENT}

EOF
    fi

    # Continue with the rest of the configuration
    cat << EOF >> ${OVPN_SERVER_CONF}
# Certificate and key files
ca ${OVPN_PKI}/ca.crt
cert ${OVPN_PKI}/issued/server.crt
key ${OVPN_PKI}/private/server.key
dh ${OVPN_PKI}/dh.pem

# TLS authentication
tls-crypt-v2 ${OVPN_PKI}/private/server.pem

# Client configuration
client-to-client
keepalive 10 60

# Push routes and DNS to clients (IPv4)
push "redirect-gateway def1"
push "dhcp-option DNS ${OVPN_DNS}"
push "dhcp-option DOMAIN ${OVPN_DOMAIN}"
push "persist-tun"
push "persist-key"

EOF

    # Add IPv6 push routes if enabled
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        cat << EOF >> ${OVPN_SERVER_CONF}
# IPv6 push routes and DNS
push "route-ipv6 2000::/3"
push "dhcp-option DNS6 ${OVPN_IPV6_DNS}"

EOF
    fi

    # Continue with security and logging
    cat << EOF >> ${OVPN_SERVER_CONF}
# Privileges and security
user nobody
group nogroup
persist-tun
persist-key

# Logging
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
EOF

    # Add performance settings (bandwidth limiting only)
    # Note: Compression is NOT configured due to deprecation and stability issues
    # See: https://community.openvpn.net/Pages/Compression

    # Add bandwidth limiting if enabled
    if [ "$OVPN_BANDWIDTH_LIMIT" -gt 0 ] 2>/dev/null; then
        cat << EOF >> ${OVPN_SERVER_CONF}
# Bandwidth limiting (${OVPN_BANDWIDTH_LIMIT} bytes/sec)
shaper ${OVPN_BANDWIDTH_LIMIT}

EOF
    fi

    # Add CRL section
    cat << EOF >> ${OVPN_SERVER_CONF}
# Certificate Revocation List (uncomment after first revocation)
# crl-verify ${OVPN_PKI}/crl.pem
EOF
    
    echo ""
    echo "Server configuration created: $OVPN_SERVER_CONF"
    echo ""

    # Ensure UCI instance exists and is configured
    echo "Updating UCI configuration..."
    ensure_uci_instance "$OVPN_INSTANCE"
    uci set openvpn.${OVPN_INSTANCE}.config="$OVPN_SERVER_CONF"
    uci set openvpn.${OVPN_INSTANCE}.enabled=1
    uci commit openvpn
    echo "UCI instance '$OVPN_INSTANCE' updated"
    echo ""

    # Enable OpenVPN service to start at boot
    echo "Checking autostart configuration..."
    if /etc/init.d/openvpn enabled; then
        echo "  OpenVPN autostart already enabled"
    else
        echo "  Enabling OpenVPN service to start at boot..."
        /etc/init.d/openvpn enable
        echo "  ✓ OpenVPN will now start automatically on router reboot"
    fi
    echo ""

    echo "IMPORTANT: Review the configuration file before restarting OpenVPN"
    echo ""

    read -p "View the generated configuration? (y/n): " view
    if [ "$view" = "y" ] || [ "$view" = "Y" ]; then
        echo ""
        echo "=== Generated Configuration ==="
        cat "$OVPN_SERVER_CONF"
        echo "=== End of Configuration ==="
        echo ""
    fi

    # Check firewall
    check_firewall

    read -p "Restart OpenVPN instance '$OVPN_INSTANCE' to apply changes? (y/n): " restart
    if [ "$restart" = "y" ] || [ "$restart" = "Y" ]; then
        /etc/init.d/openvpn restart "$OVPN_INSTANCE"
        echo "OpenVPN instance '$OVPN_INSTANCE' restarted"
    else
        echo "Remember to restart OpenVPN: /etc/init.d/openvpn restart $OVPN_INSTANCE"
    fi
}

# Function to restore server.conf from backup
restore_server_conf() {
    local confirm
    local restart

    echo ""
    echo "=== Restore OpenVPN Server Configuration from Backup ==="
    echo ""

    if [ ! -f "$OVPN_SERVER_BACKUP" ]; then
        echo "Error: No backup file found at $OVPN_SERVER_BACKUP"
        return 1
    fi

    echo "Backup found: $OVPN_SERVER_BACKUP"
    echo ""
    echo "WARNING: This will restore the server configuration from backup"
    echo "Current configuration will be overwritten."
    echo ""
    read -p "Continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo "Restore cancelled."
        return 0
    fi
    
    echo "Restoring configuration..."
    cp "$OVPN_SERVER_BACKUP" "$OVPN_SERVER_CONF"
    
    echo "Configuration restored from backup"
    echo ""
    
    read -p "Restart OpenVPN daemon? (y/n): " restart
    if [ "$restart" = "y" ] || [ "$restart" = "Y" ]; then
        /etc/init.d/openvpn restart
        echo "OpenVPN daemon restarted"
    fi
}

# Function to list all issued clients
list_clients() {
    local cert
    local basename

    echo ""
    echo "=== Current OpenVPN Clients ==="
    if [ -d "${OVPN_PKI}/issued" ]; then
        for cert in ${OVPN_PKI}/issued/*.crt; do
            if [ -f "$cert" ]; then
                basename=$(basename "$cert" .crt)
                if [ "$basename" != "server" ]; then
                    echo "  - $basename"
                fi
            fi
        done
    else
        echo "No issued directory found at ${OVPN_PKI}/issued"
    fi
    echo ""
}

# Function to check certificate expiration dates
check_expiration() {
    local current_date
    local warning_threshold
    local cert
    local basename
    local not_after
    local exp_date
    local days_left

    echo ""
    echo "=== Certificate Expiration Status ==="
    echo ""

    if [ ! -d "${OVPN_PKI}/issued" ]; then
        echo "No issued directory found at ${OVPN_PKI}/issued"
        return 1
    fi

    current_date=$(date +%s)
    warning_threshold=$((30 * 24 * 60 * 60))  # 30 days in seconds

    for cert in ${OVPN_PKI}/issued/*.crt; do
        if [ -f "$cert" ]; then
            basename=$(basename "$cert" .crt)

            # Get expiration date
            not_after=$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)
            exp_date=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$not_after" +%s 2>/dev/null)

            if [ -n "$exp_date" ]; then
                days_left=$(( ($exp_date - $current_date) / 86400 ))
                
                if [ $days_left -lt 0 ]; then
                    echo "  [EXPIRED] $basename: $days_left days"
                elif [ $days_left -lt 30 ]; then
                    echo "  [WARNING] $basename: $days_left days left"
                elif [ $days_left -lt 90 ]; then
                    echo "  [SOON]    $basename: $days_left days left"
                else
                    echo "  [OK]      $basename: $days_left days left"
                fi
            else
                echo "  [ERROR]   $basename: Could not parse expiration date"
            fi
        fi
    done
    echo ""
}

# Function to show certificate details
show_cert_details() {
    local counter
    local cert
    local basename
    local cert_name
    local cert_path

    echo ""
    echo "=== Available Certificates ==="

    counter=1
    if [ -d "${OVPN_PKI}/issued" ]; then
        for cert in ${OVPN_PKI}/issued/*.crt; do
            if [ -f "$cert" ]; then
                basename=$(basename "$cert" .crt)
                echo "  $counter) $basename"
                counter=$((counter + 1))
            fi
        done
    fi

    if [ "$counter" -eq 1 ]; then
        echo "No certificates found."
        return 1
    fi

    echo ""
    read -p "Enter certificate name to view details: " cert_name

    if [ -z "$cert_name" ]; then
        echo "Error: No certificate name entered"
        return 1
    fi

    cert_path="${OVPN_PKI}/issued/${cert_name}.crt"
    
    if [ ! -f "$cert_path" ]; then
        echo "Error: Certificate '$cert_name' not found"
        return 1
    fi
    
    echo ""
    echo "=== Certificate Details for: $cert_name ==="
    echo ""
    
    # Extract and display key information
    openssl x509 -in "$cert_path" -noout -subject -issuer -dates -serial -purpose
    
    echo ""
}

# Function to renew a certificate
renew_certificate() {
    local counter
    local cert
    local basename
    local cert_name
    local confirm
    local regen

    echo ""
    echo "=== Renew Certificate ==="
    echo ""
    echo "Available certificates:"

    counter=1
    if [ -d "${OVPN_PKI}/issued" ]; then
        for cert in ${OVPN_PKI}/issued/*.crt; do
            if [ -f "$cert" ]; then
                basename=$(basename "$cert" .crt)
                if [ "$basename" != "server" ]; then
                    echo "  $counter) $basename"
                    counter=$((counter + 1))
                fi
            fi
        done
    fi

    if [ "$counter" -eq 1 ]; then
        echo "No client certificates found to renew."
        return 1
    fi

    echo ""
    read -p "Enter certificate name to renew: " cert_name

    if [ -z "$cert_name" ]; then
        echo "Error: No certificate name entered"
        return 1
    fi

    if [ ! -f "${OVPN_PKI}/issued/${cert_name}.crt" ]; then
        echo "Error: Certificate '$cert_name' not found"
        return 1
    fi

    echo ""
    echo "WARNING: This will renew the certificate for: $cert_name"
    echo "The old certificate will be marked as expired."
    read -p "Continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo "Renewal cancelled."
        return 0
    fi
    
    echo ""
    echo "Renewing certificate for $cert_name..."
    
    # Use easyrsa renew command (available in easyrsa 3.2.1+)
    # If renew is not available, use the expire + sign-req method
    if easyrsa help 2>&1 | grep -q "renew"; then
        easyrsa renew "$cert_name" nopass
    else
        echo "Note: Using expire + sign-req method (easyrsa < 3.2.1)"
        easyrsa expire "$cert_name" && easyrsa sign-req client "$cert_name"
    fi
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "Certificate renewed successfully!"
        echo "Note: You will need to regenerate the .ovpn config file for this client."
        echo ""
        read -p "Regenerate .ovpn file now? (y/n): " regen
        if [ "$regen" = "y" ] || [ "$regen" = "Y" ]; then
            generate_single_ovpn "$cert_name"
        fi
    else
        echo "Error: Certificate renewal failed"
    fi
}

# Function to generate a single .ovpn file
generate_single_ovpn() {
    local OVPN_ID="$1"
    local OVPN_CA
    local OVPN_TC
    local OVPN_KEY
    local OVPN_CERT
    local OVPN_CONF

    if [ -z "$OVPN_ID" ]; then
        echo "Error: No client name provided"
        return 1
    fi

    if [ ! -f "${OVPN_PKI}/issued/${OVPN_ID}.crt" ]; then
        echo "Error: Certificate for '$OVPN_ID' not found"
        return 1
    fi

    echo "Generating .ovpn file for $OVPN_ID..."

    umask go=
    OVPN_CA="$(openssl x509 -in ${OVPN_PKI}/ca.crt)"
    OVPN_TC="$(cat ${OVPN_PKI}/private/${OVPN_ID}.pem)"
    OVPN_KEY="$(cat ${OVPN_PKI}/private/${OVPN_ID}.key)"
    OVPN_CERT="$(openssl x509 -in ${OVPN_PKI}/issued/${OVPN_ID}.crt)"

    OVPN_CONF="${OVPN_DIR}/${OVPN_ID}.ovpn"
    
    cat << EOF > ${OVPN_CONF}
user nobody
group nogroup
dev tun
nobind
client
remote ${OVPN_SERV} ${OVPN_PORT} ${OVPN_PROTO}
auth-nocache
remote-cert-tls server
<tls-crypt-v2>
${OVPN_TC}
</tls-crypt-v2>
<key>
${OVPN_KEY}
</key>
<cert>
${OVPN_CERT}
</cert>
<ca>
${OVPN_CA}
</ca>
EOF
    
    echo "Generated: ${OVPN_CONF}"
}

# Function to generate all .ovpn files
generate_all_ovpn() {
    local confirm
    local OVPN_DH
    local OVPN_CA
    local cert_file
    local OVPN_ID
    local OVPN_CERT
    local OVPN_EKU
    local OVPN_TC
    local OVPN_KEY
    local OVPN_CONF

    echo ""
    echo "=== Generate Client Configuration Files ==="
    echo ""
    echo "This will generate .ovpn files for all client certificates."
    echo "Output directory: $OVPN_DIR"
    echo ""
    read -p "Continue? (y/n): " confirm

    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Cancelled."
        return 0
    fi

    echo ""
    echo "Generating configuration files..."
    echo ""

    umask go=
    OVPN_DH="$(cat ${OVPN_PKI}/dh.pem)"
    OVPN_CA="$(openssl x509 -in ${OVPN_PKI}/ca.crt)"

    ls ${OVPN_PKI}/issued/*.crt 2>/dev/null | while read -r cert_file; do
        OVPN_ID=$(basename "$cert_file" .crt)

        OVPN_CERT="$(openssl x509 -in ${cert_file})"
        OVPN_EKU="$(echo "${OVPN_CERT}" | openssl x509 -noout -purpose)"
        
        case ${OVPN_EKU} in
            (*"SSL server : Yes"*)
                # Skip server certificates in batch client generation
                echo "Skipping server certificate: ${OVPN_ID}"
                ;;
            (*"SSL client : Yes"*)
                # Generate client config
                OVPN_TC="$(cat ${OVPN_PKI}/private/${OVPN_ID}.pem)"
                OVPN_KEY="$(cat ${OVPN_PKI}/private/${OVPN_ID}.key)"
                
                OVPN_CONF="${OVPN_DIR}/${OVPN_ID}.ovpn"
                cat << EOF > ${OVPN_CONF}
user nobody
group nogroup
dev tun
nobind
client
remote ${OVPN_SERV} ${OVPN_PORT} ${OVPN_PROTO}
auth-nocache
remote-cert-tls server
<tls-crypt-v2>
${OVPN_TC}
</tls-crypt-v2>
<key>
${OVPN_KEY}
</key>
<cert>
${OVPN_CERT}
</cert>
<ca>
${OVPN_CA}
</ca>
EOF
                echo "Generated client config: ${OVPN_CONF}"
                ;;
        esac
    done
    
    echo ""
    echo "Configuration files generated in: $OVPN_DIR"
    echo ""
    ls -lh ${OVPN_DIR}/*.ovpn 2>/dev/null
    echo ""
}

# Function to create new client
create_client() {
    local NEW_CLIENT
    local gen_ovpn
    local response

    read -p "Enter client name: " NEW_CLIENT

    if [ -z "$NEW_CLIENT" ]; then
        echo "Error: Client name cannot be empty"
        return 1
    fi

    echo "Building new keys for $NEW_CLIENT"
    easyrsa build-client-full $NEW_CLIENT nopass
    openvpn --tls-crypt-v2 ${EASYRSA_PKI}/private/server.pem \
        --genkey tls-crypt-v2-client ${EASYRSA_PKI}/private/$NEW_CLIENT.pem

    echo ""
    read -p "Generate .ovpn config file? (y/n): " gen_ovpn
    if [ "$gen_ovpn" = "y" ] || [ "$gen_ovpn" = "Y" ]; then
        generate_single_ovpn "$NEW_CLIENT"
    fi

    echo ""
    read -t 10 -p "OpenVPN Daemon restart. 10s timeout. Continue? (y/n): " response
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        /etc/init.d/openvpn restart
        echo "OpenVPN daemon restarted"
    else
        echo "OpenVPN daemon not restarted."
        echo "Keys will not be valid until the daemon refreshes them"
    fi
}

# Function to revoke a client
revoke_client() {
    local counter
    local cert
    local basename
    local CLIENT_TO_REVOKE
    local confirm
    local response

    echo ""
    echo "=== Available Clients to Revoke ==="

    counter=1
    if [ -d "${OVPN_PKI}/issued" ]; then
        for cert in ${OVPN_PKI}/issued/*.crt; do
            if [ -f "$cert" ]; then
                basename=$(basename "$cert" .crt)
                if [ "$basename" != "server" ]; then
                    echo "  $counter) $basename"
                    counter=$((counter + 1))
                fi
            fi
        done
    fi

    if [ "$counter" -eq 1 ]; then
        echo "No clients found to revoke."
        return 1
    fi

    echo ""
    read -p "Enter client name to revoke: " CLIENT_TO_REVOKE

    if [ -z "$CLIENT_TO_REVOKE" ]; then
        echo "Error: No client name entered"
        return 1
    fi

    if [ ! -f "${OVPN_PKI}/issued/${CLIENT_TO_REVOKE}.crt" ]; then
        echo "Error: Client '$CLIENT_TO_REVOKE' not found in issued certificates"
        return 1
    fi

    echo ""
    echo "WARNING: You are about to revoke certificate for: $CLIENT_TO_REVOKE"
    read -p "Are you sure? (yes/no): " confirm
    
    case $confirm in
        yes)
            echo "Revoking certificate for $CLIENT_TO_REVOKE..."
            easyrsa revoke $CLIENT_TO_REVOKE
            
            echo "Generating Certificate Revocation List (CRL)..."
            easyrsa gen-crl
            
            echo ""
            echo "Certificate revoked successfully."
            echo "CRL updated at: ${OVPN_PKI}/crl.pem"
            echo ""
            echo "NOTE: Ensure 'crl-verify' is enabled in your server.conf"
            echo ""
            
            read -p "Restart OpenVPN daemon to apply changes? (y/n): " response
            if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
                /etc/init.d/openvpn restart
                echo "OpenVPN daemon restarted"
            else
                echo "Remember to restart OpenVPN daemon for changes to take effect"
            fi
            ;;
        *)
            echo "Revocation cancelled."
            ;;
    esac
}

# Function to monitor VPN address usage (IPv4 and IPv6)
monitor_vpn_usage() {
    local instance_count
    local instances
    local inst
    local status
    local choice
    local selected_instance

    echo ""
    echo "=== VPN Address Usage Monitor ==="
    echo ""

    # Check if any OpenVPN process is running
    if ! pgrep openvpn >/dev/null; then
        echo "No OpenVPN processes are running"
        return 1
    fi

    # List available instances
    echo "Available OpenVPN instances:"
    echo ""

    instance_count=0
    instances=""

    if uci show openvpn >/dev/null 2>&1; then
        instances=$(uci show openvpn 2>/dev/null | grep "=openvpn$" | cut -d'.' -f2 | cut -d'=' -f1)

        for inst in $instances; do
            instance_count=$((instance_count + 1))

            # Check if running
            if pgrep -f "[o]penvpn.*${inst}" >/dev/null 2>&1; then
                status="RUNNING"
            else
                status="stopped"
            fi

            echo "  $instance_count) $inst ($status)"
        done
    fi

    echo ""
    echo "  a) Monitor all instances"
    echo "  c) Cancel"
    echo ""

    if [ $instance_count -eq 0 ]; then
        echo "No UCI instances found"
        return 1
    fi

    read -p "Select instance to monitor: " choice

    selected_instance=""

    case "$choice" in
        [0-9]*)
            # User selected a number
            selected_instance=$(echo "$instances" | sed -n "${choice}p")

            if [ -z "$selected_instance" ]; then
                echo "Invalid selection"
                return 1
            fi
            ;;
        a|A)
            # Monitor all instances
            selected_instance="all"
            ;;
        c|C)
            echo "Cancelled"
            return 0
            ;;
        *)
            echo "Invalid option"
            return 1
            ;;
    esac

    echo ""

    # Monitor selected instance(s)
    if [ "$selected_instance" = "all" ]; then
        # Monitor all instances
        for inst in $instances; do
            monitor_single_instance "$inst"
        done
    else
        # Monitor single instance
        monitor_single_instance "$selected_instance"
    fi

    echo ""
}

# Helper function to monitor a single instance
monitor_single_instance() {
    local instance="$1"
    local tun_interfaces
    local tun_if
    local ipv4_addrs
    local pool_network
    local pool_prefix
    local max_hosts
    local ipv4_neighbors
    local remaining
    local neighbors
    local ipv6_addrs
    local addr_count
    local openvpn_pid
    local total_clients
    local line
    local client_name
    local real_addr
    local virtual_ipv4
    local virtual_ipv6
    local bytes_recv
    local bytes_sent
    local connected_since
    local bytes_recv_mb
    local bytes_sent_mb

    echo "=================================================="
    echo "Monitoring Instance: $instance"
    echo "=================================================="
    echo ""

    # Find tun interfaces
    tun_interfaces=$(ip link show | grep -o "tun[0-9]*" | sort -u)

    if [ -z "$tun_interfaces" ]; then
        echo "No VPN tunnel interfaces found"
        return 1
    fi

    for tun_if in $tun_interfaces; do
        echo "=================================================="
        echo "Interface: $tun_if"
        echo "=================================================="
        echo ""

        # === IPv4 Monitoring ===
        echo "--- IPv4 Status ---"
        ipv4_addrs=$(ip -4 addr show dev "$tun_if" 2>/dev/null | grep "inet ")

        if [ -z "$ipv4_addrs" ]; then
            echo "  No IPv4 addresses configured"
        else
            echo "  IPv4 Addresses:"
            echo "$ipv4_addrs" | while read line; do
                echo "    $line"
            done

            # Extract network and calculate pool info
            pool_network=$(echo "$ipv4_addrs" | head -1 | awk '{print $2}' | cut -d'/' -f1)
            pool_prefix=$(echo "$ipv4_addrs" | head -1 | awk '{print $2}' | cut -d'/' -f2)

            echo ""
            echo "  IPv4 Network: $pool_network/$pool_prefix"

            # Calculate pool size based on netmask
            if [ "$pool_prefix" = "24" ]; then
                max_hosts=253  # /24 = 254 usable, minus 1 for server
            elif [ "$pool_prefix" = "25" ]; then
                max_hosts=125
            elif [ "$pool_prefix" = "26" ]; then
                max_hosts=61
            elif [ "$pool_prefix" = "27" ]; then
                max_hosts=29
            else
                max_hosts="unknown"
            fi

            # Count connected IPv4 clients from ARP
            ipv4_neighbors=$(ip -4 neigh show dev "$tun_if" | grep -v "FAILED" | wc -l)

            echo "  Connected IPv4 clients: $ipv4_neighbors"
            if [ "$max_hosts" != "unknown" ]; then
                remaining=$((max_hosts - ipv4_neighbors))
                echo "  Maximum clients (/$pool_prefix): $max_hosts"
                echo "  Remaining capacity: $remaining"
            fi

            echo ""
            echo "  IPv4 Neighbors (ARP table):"
            neighbors=$(ip -4 neigh show dev "$tun_if" | grep -v "FAILED")
            if [ -z "$neighbors" ]; then
                echo "    No IPv4 neighbors detected"
            else
                echo "$neighbors" | while read line; do
                    echo "    $line"
                done
            fi
        fi

        echo ""

        # === IPv6 Monitoring ===
        echo "--- IPv6 Status ---"
        ipv6_addrs=$(ip -6 addr show dev "$tun_if" 2>/dev/null | grep "inet6" | grep -v "fe80::")

        if [ -z "$ipv6_addrs" ]; then
            echo "  No IPv6 addresses configured"
        else
            echo "  IPv6 Addresses:"
            echo "$ipv6_addrs" | while read line; do
                echo "    $line"
            done

            # Count addresses (excluding link-local)
            addr_count=$(echo "$ipv6_addrs" | wc -l)
            echo ""
            echo "  Total IPv6 addresses: $addr_count"

            if [ -n "$OVPN_IPV6_POOL_SIZE" ] && [ "$OVPN_IPV6_POOL_SIZE" -gt 0 ]; then
                remaining=$((OVPN_IPV6_POOL_SIZE - addr_count))
                echo "  Configured limit: $OVPN_IPV6_POOL_SIZE"
                echo "  Remaining capacity: $remaining"
            fi

            echo ""
            echo "  Connected IPv6 Clients (NDP table):"
            neighbors=$(ip -6 neigh show dev "$tun_if" | grep -v "fe80::" | grep -v "FAILED")

            if [ -z "$neighbors" ]; then
                echo "    No IPv6 neighbors detected"
            else
                echo "$neighbors" | while read line; do
                    echo "    $line"
                done
            fi
        fi

        echo ""
    done

    # Check OpenVPN status log if available
    if [ -f "/var/log/openvpn-status.log" ]; then
        echo "=================================================="
        echo "OpenVPN Client Status (from status log)"
        echo "=================================================="
        echo ""

        # Force OpenVPN to update status file by sending SIGUSR2
        # Find PID for this specific instance
        openvpn_pid=$(pgrep -f "[o]penvpn.*${instance}" | head -1)
        if [ -n "$openvpn_pid" ]; then
            echo "Updating status file for instance '$instance' (sending SIGUSR2 to PID $openvpn_pid)..."
            kill -USR2 $openvpn_pid 2>/dev/null

            # Wait briefly for status file to be written
            sleep 1
            echo ""
        else
            echo "Warning: Could not find OpenVPN process for instance '$instance'"
            echo "Status file may be outdated or instance not running"
            echo ""
        fi

        # Count total clients
        total_clients=$(grep "^CLIENT_LIST" /var/log/openvpn-status.log 2>/dev/null | grep -v "HEADER" | wc -l)
        echo "Total connected clients: $total_clients"
        echo ""

        grep "^CLIENT_LIST" /var/log/openvpn-status.log 2>/dev/null | while read line; do
            # Parse: CLIENT_LIST,name,real_addr,virtual_addr,virtual_ipv6_addr,bytes_recv,bytes_sent,connected_since,connected_since_epoch,username
            client_name=$(echo "$line" | cut -d',' -f2)
            real_addr=$(echo "$line" | cut -d',' -f3)
            virtual_ipv4=$(echo "$line" | cut -d',' -f4)
            virtual_ipv6=$(echo "$line" | cut -d',' -f5)
            bytes_recv=$(echo "$line" | cut -d',' -f6)
            bytes_sent=$(echo "$line" | cut -d',' -f7)
            connected_since=$(echo "$line" | cut -d',' -f8)

            if [ -n "$client_name" ] && [ "$client_name" != "HEADER" ]; then
                echo "  Client: $client_name"
                echo "    Real address: $real_addr"
                echo "    Virtual IPv4: $virtual_ipv4"
                if [ -n "$virtual_ipv6" ] && [ "$virtual_ipv6" != "" ]; then
                    echo "    Virtual IPv6: $virtual_ipv6"
                fi

                # Convert bytes to human readable
                if [ -n "$bytes_recv" ] && [ "$bytes_recv" -gt 0 ] 2>/dev/null; then
                    bytes_recv_mb=$((bytes_recv / 1024 / 1024))
                    bytes_sent_mb=$((bytes_sent / 1024 / 1024))
                    echo "    Data: ↓ ${bytes_recv_mb} MB / ↑ ${bytes_sent_mb} MB"
                fi

                echo "    Connected since: $connected_since"
                echo ""
            fi
        done
    else
        echo "=================================================="
        echo "Note: OpenVPN status log not found at /var/log/openvpn-status.log"
        echo "      Detailed client information not available"
        echo "=================================================="
    fi

    echo ""
}

# Function to toggle IPv6 configuration
toggle_ipv6() {
    local ipv6_option
    local new_mode
    local check
    local confirm_dhcpv6
    local new_ipv6_pool
    local new_size
    local confirm
    local mode_choice
    local confirm_conflict

    echo ""
    echo "=== IPv6 Configuration ==="
    echo ""
    echo "Current IPv6 status: $OVPN_IPV6_ENABLE"
    echo ""

    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "IPv6 is currently ENABLED"
        echo "  Mode: $OVPN_IPV6_MODE"
        echo "  IPv6 VPN Subnet: $OVPN_IPV6_POOL"
        echo "  IPv6 DNS Server: $OVPN_IPV6_DNS"
        echo "  Max Clients: $OVPN_IPV6_POOL_SIZE"
        echo ""
        echo "Options:"
        echo "  1) Change IPv6 mode (static/dhcpv6)"
        echo "  2) Change IPv6 subnet"
        echo "  3) Change max clients limit"
        echo "  4) Disable IPv6"
        echo "  5) Cancel"
        echo ""
        read -p "Select option (1-5): " ipv6_option

        case $ipv6_option in
            1)
                echo ""
                echo "Current mode: $OVPN_IPV6_MODE"
                echo ""
                echo "Available modes:"
                echo "  static  - Simple static pool allocation (recommended for most users)"
                echo "  dhcpv6  - Advanced DHCPv6-PD with tracked leases (for advanced users)"
                echo ""
                read -p "Enter mode (static/dhcpv6): " new_mode
                if [ "$new_mode" = "static" ]; then
                    OVPN_IPV6_MODE="$new_mode"
                    echo "Mode changed to: $OVPN_IPV6_MODE"
                    echo "Note: Regenerate server.conf (option 1) to apply changes"
                elif [ "$new_mode" = "dhcpv6" ]; then
                    echo ""
                    echo "WARNING: DHCPv6 mode requires manual configuration"
                    echo ""
                    read -p "Check prerequisites and show configuration guide? (y/n): " check
                    if [ "$check" = "y" ] || [ "$check" = "Y" ]; then
                        check_dhcpv6_prerequisites
                        echo ""
                        read -p "Continue with DHCPv6 mode anyway? (yes/no): " confirm_dhcpv6
                        if [ "$confirm_dhcpv6" = "yes" ]; then
                            OVPN_IPV6_MODE="dhcpv6"
                            echo "Mode changed to: $OVPN_IPV6_MODE"
                            echo "Note: You MUST configure odhcpd manually before this will work"
                            echo "Note: Regenerate server.conf (option 1) to apply changes"
                        else
                            echo "Staying with current mode: $OVPN_IPV6_MODE"
                        fi
                    else
                        echo "Cancelled. Staying with current mode: $OVPN_IPV6_MODE"
                    fi
                else
                    echo "Invalid mode. No changes made."
                fi
                ;;
            2)
                echo ""
                echo "Current IPv6 subnet: $OVPN_IPV6_POOL"
                echo ""
                echo "For globally routable: Use a /64 from your ISP's delegation"
                echo "For private ULA: Generate at https://unique-local-ipv6.com/"
                echo ""
                read -p "Enter new IPv6 subnet: " new_ipv6_pool
                if [ -n "$new_ipv6_pool" ]; then
                    # Check for conflicts with LAN
                    if check_ipv6_subnet_conflict "$new_ipv6_pool"; then
                        OVPN_IPV6_POOL="$new_ipv6_pool"
                        OVPN_IPV6_DNS="${OVPN_IPV6_POOL%::*}::1"
                        echo "IPv6 subnet changed to: $OVPN_IPV6_POOL"
                        echo "Note: Regenerate server.conf (option 1) to apply changes"
                    else
                        echo "Subnet NOT changed due to conflict. Please choose a different subnet."
                    fi
                fi
                ;;
            3)
                echo ""
                echo "Current max clients: $OVPN_IPV6_POOL_SIZE"
                read -p "Enter new max clients limit: " new_size
                if [ -n "$new_size" ] && [ "$new_size" -gt 0 ] 2>/dev/null; then
                    OVPN_IPV6_POOL_SIZE="$new_size"
                    echo "Max clients limit changed to: $OVPN_IPV6_POOL_SIZE"
                else
                    echo "Invalid number. No changes made."
                fi
                ;;
            4)
                echo ""
                echo "WARNING: Disabling IPv6 will cause IPv6 traffic to leak outside the VPN tunnel!"
                echo ""
                echo "VPN clients with IPv6 connectivity will send IPv6 traffic through their"
                echo "local connection, NOT through the VPN. This exposes their real IPv6 address."
                echo ""
                read -p "Disable IPv6 support? (yes/no): " confirm
                if [ "$confirm" = "yes" ]; then
                    OVPN_IPV6_ENABLE="no"
                    echo ""
                    echo "IPv6 support disabled"
                    echo ""
                    echo "IMPORTANT: Client IPv6 traffic will NOT go through the VPN!"
                    echo "Advise your VPN users to either:"
                    echo "  - Disable IPv6 on their devices, OR"
                    echo "  - Use firewall rules to block IPv6"
                    echo ""
                    echo "Note: Regenerate server.conf (option 1) to apply changes"
                else
                    echo "No changes made"
                fi
                ;;
            *)
                echo "Cancelled"
                ;;
        esac
    else
        echo "IPv6 is currently DISABLED"
        echo ""
        echo "WARNING: IPv6 traffic from VPN clients will leak outside the tunnel!"
        echo "Clients with IPv6 connectivity will send IPv6 traffic through their"
        echo "local connection, exposing their real IPv6 address."
        echo ""
        echo "Enabling IPv6 will:"
        echo "  1. Add IPv6 subnet to VPN tunnel"
        echo "  2. Push IPv6 routes to clients"
        echo "  3. Enable IPv6 DNS for VPN clients"
        echo ""
        read -p "Enable IPv6 support? (yes/no): " confirm

        if [ "$confirm" = "yes" ]; then
            echo ""
            echo "Select IPv6 mode:"
            echo "  1) Static pool (recommended) - Simple, uses server-ipv6 directive"
            echo "  2) DHCPv6-PD (advanced) - Tracked leases, requires odhcpd configuration"
            echo ""
            read -p "Select mode (1-2): " mode_choice

            if [ "$mode_choice" = "2" ]; then
                echo ""
                echo "WARNING: DHCPv6 mode is ADVANCED and requires manual configuration"
                echo ""
                read -p "Check prerequisites and show configuration guide? (y/n): " check
                if [ "$check" = "y" ] || [ "$check" = "Y" ]; then
                    check_dhcpv6_prerequisites
                    echo ""
                    read -p "Continue with DHCPv6 mode anyway? (yes/no): " confirm_dhcpv6
                    if [ "$confirm_dhcpv6" = "yes" ]; then
                        OVPN_IPV6_MODE="dhcpv6"
                        echo ""
                        echo "DHCPv6 mode selected"
                        echo "NOTE: You MUST configure odhcpd manually before this will work"
                    else
                        OVPN_IPV6_MODE="static"
                        echo ""
                        echo "Falling back to Static pool mode (recommended)"
                    fi
                else
                    OVPN_IPV6_MODE="static"
                    echo ""
                    echo "Static pool mode selected (default)"
                fi
            else
                OVPN_IPV6_MODE="static"
                echo ""
                echo "Static pool mode selected (default)"
            fi

            echo ""
            echo "Current IPv6 subnet: $OVPN_IPV6_POOL"
            echo ""
            echo "For globally routable: Use a /64 from your ISP's delegation"
            echo "For private ULA: Generate at https://unique-local-ipv6.com/"
            echo ""
            read -p "Enter IPv6 subnet (or press Enter to keep current): " new_ipv6_pool

            if [ -n "$new_ipv6_pool" ]; then
                # Check for conflicts with LAN
                if ! check_ipv6_subnet_conflict "$new_ipv6_pool"; then
                    echo "WARNING: Using conflicting subnet anyway. This may cause problems."
                    read -p "Continue? (yes/no): " confirm_conflict
                    if [ "$confirm_conflict" != "yes" ]; then
                        echo "Keeping current subnet: $OVPN_IPV6_POOL"
                        new_ipv6_pool=""
                    fi
                fi

                if [ -n "$new_ipv6_pool" ]; then
                    OVPN_IPV6_POOL="$new_ipv6_pool"
                    OVPN_IPV6_DNS="${OVPN_IPV6_POOL%::*}::1"
                fi
            fi

            echo ""
            read -p "Enter max clients limit (default 253): " new_size
            if [ -n "$new_size" ] && [ "$new_size" -gt 0 ] 2>/dev/null; then
                OVPN_IPV6_POOL_SIZE="$new_size"
            fi

            OVPN_IPV6_ENABLE="yes"
            echo ""
            echo "IPv6 support enabled"
            echo "  Mode: $OVPN_IPV6_MODE"
            echo "  IPv6 VPN Subnet: $OVPN_IPV6_POOL"
            echo "  IPv6 DNS Server: $OVPN_IPV6_DNS"
            echo "  Max Clients: $OVPN_IPV6_POOL_SIZE"
            echo ""
            echo "Note: Regenerate server.conf (option 1) to apply changes"
        else
            echo "No changes made"
        fi
    fi

    echo ""
}

# Function to configure performance settings
configure_performance() {
    local OVPN_BW_MBPS
    local perf_option
    local new_limit

    echo ""
    echo "=== Performance Configuration ==="
    echo ""
    echo "Current Performance Settings:"
    echo ""
    echo "Compression:"
    echo "  Status: NOT CONFIGURED (deprecated by OpenVPN project)"
    echo "  See: https://community.openvpn.net/Pages/Compression"
    echo "  Note: Compression directive omitted due to stability issues"
    echo ""
    echo "Bandwidth Limiting:"
    if [ "$OVPN_BANDWIDTH_LIMIT" -gt 0 ] 2>/dev/null; then
        OVPN_BW_MBPS=$(awk "BEGIN {printf \"%.2f\", ($OVPN_BANDWIDTH_LIMIT * 8) / 1000000}")
        echo "  Status: ENABLED"
        echo "  Limit: $OVPN_BANDWIDTH_LIMIT bytes/sec (~${OVPN_BW_MBPS} Mbps)"
    else
        echo "  Status: DISABLED (unlimited)"
    fi
    echo ""
    echo "Options:"
    echo "  1) Configure bandwidth limiting"
    echo "  2) Cancel"
    echo ""
    read -p "Select option (1-2): " perf_option

    case $perf_option in
        1)
            echo ""
            echo "=== Bandwidth Limiting Configuration ==="
            echo ""
            if [ "$OVPN_BANDWIDTH_LIMIT" -gt 0 ] 2>/dev/null; then
                OVPN_BW_MBPS=$(awk "BEGIN {printf \"%.2f\", ($OVPN_BANDWIDTH_LIMIT * 8) / 1000000}")
                echo "Current limit: $OVPN_BANDWIDTH_LIMIT bytes/sec (~${OVPN_BW_MBPS} Mbps)"
            else
                echo "Current limit: DISABLED (unlimited)"
            fi
            echo ""
            echo "Enter bandwidth limit in bytes per second:"
            echo "  Examples:"
            echo "    125000    = ~1 Mbps"
            echo "    1000000   = ~8 Mbps"
            echo "    5000000   = ~40 Mbps"
            echo "    10000000  = ~80 Mbps"
            echo "    0         = Unlimited (disable limiting)"
            echo ""
            read -p "Enter bandwidth limit (bytes/sec): " new_limit

            if [ -n "$new_limit" ] && [ "$new_limit" -ge 0 ] 2>/dev/null; then
                OVPN_BANDWIDTH_LIMIT="$new_limit"
                echo ""
                if [ "$OVPN_BANDWIDTH_LIMIT" -gt 0 ]; then
                    OVPN_BW_MBPS=$(awk "BEGIN {printf \"%.2f\", ($OVPN_BANDWIDTH_LIMIT * 8) / 1000000}")
                    echo "Bandwidth limit set to: $OVPN_BANDWIDTH_LIMIT bytes/sec (~${OVPN_BW_MBPS} Mbps)"
                else
                    echo "Bandwidth limiting disabled (unlimited)"
                fi
                echo "Note: Regenerate server.conf (option 1) to apply changes"
            else
                echo "Invalid number. No changes made."
            fi
            ;;
        *)
            echo "Cancelled"
            ;;
    esac

    echo ""
}

key_management_first_time() {

    # Configuration parameters
    export EASYRSA_PKI="${OVPN_PKI}"
    export EASYRSA_TEMP_DIR="/tmp"
    export EASYRSA_CERT_EXPIRE="3650"
    export EASYRSA_BATCH="1"

    # Remove and re-initialize PKI directory
    easyrsa init-pki

    # Generate DH parameters
    easyrsa gen-dh

    # Create a new CA
    easyrsa build-ca nopass

    # Generate server keys and certificate
    easyrsa build-server-full server nopass
    openvpn --genkey tls-crypt-v2-server ${EASYRSA_PKI}/private/server.pem

}

# Function to install LuCI OpenVPN web interface
install_luci_openvpn() {
    local confirm

    echo ""
    echo "=== Install LuCI OpenVPN Web Interface ==="
    echo ""
    echo "This will install luci-app-openvpn for web-based management"
    echo "The LuCI app provides:"
    echo "  - Web interface for managing OpenVPN instances"
    echo "  - Start/stop/restart controls"
    echo "  - Configuration file editing"
    echo "  - Status monitoring"
    echo ""
    echo "This script and LuCI will share the same UCI configuration"
    echo "Changes made in one will be visible in the other"
    echo ""
    echo "Requirements:"
    echo "  - Internet connection"
    echo "  - LuCI web interface installed"
    echo ""
    read -p "Continue with installation? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        echo "Installation cancelled"
        return 0
    fi

    echo ""
    echo "Updating package lists..."
    if ! opkg update; then
        echo "Error: Failed to update package lists"
        echo "Check your internet connection"
        return 1
    fi

    echo ""
    echo "Installing luci-app-openvpn..."
    if opkg install luci-app-openvpn; then
        echo ""
        echo "Installation complete!"
        echo ""
        echo "Access the LuCI OpenVPN interface at:"
        echo "  Web Interface > Services > OpenVPN"
        echo "  or"
        echo "  Web Interface > System > OpenVPN"
        echo ""
        echo "Note: You may need to refresh your browser to see the new menu"
    else
        echo ""
        echo "Error: Installation failed"
        echo "The package may already be installed or unavailable"
        return 1
    fi

    echo ""
}

# Function to check and fix file permissions
check_fix_permissions() {
    local issues_found
    local total_issues
    local current_perms
    local file
    local dir
    local fix_all
    local check_type
    local expected_perms
    local actual_perms
    local temp_issues
    local counter

    echo ""
    echo "=== OpenVPN File Permissions Check ==="
    echo ""
    echo "This will check permissions on PKI files, certificates, keys, and directories."
    echo "Incorrect permissions can cause OpenVPN to fail or create security vulnerabilities."
    echo ""

    issues_found=0
    total_issues=0

    # Check if PKI directory exists
    if [ ! -d "${OVPN_PKI}" ]; then
        echo "WARNING: PKI directory not found at ${OVPN_PKI}"
        echo "Run 'Install and initialize EasyRSA' (option 12) first"
        echo ""
        return 1
    fi

    echo "Checking permissions..."
    echo ""

    # Create temp file to store issues for batch fixing
    local temp_issues="/tmp/openvpn_perm_issues_$$"
    > "$temp_issues"  # Clear/create temp file

    # Check 1: Private keys must be 600 (CRITICAL SECURITY)
    echo "1. Checking private keys (*.key files)..."
    if [ -d "${OVPN_PKI}/private" ]; then
        for file in ${OVPN_PKI}/private/*.key; do
            if [ -f "$file" ]; then
                current_perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%Lp" "$file" 2>/dev/null)
                if [ "$current_perms" != "600" ] && [ "$current_perms" != "400" ]; then
                    echo "   [ISSUE] $(basename "$file"): $current_perms (should be 600)"
                    echo "$file|$current_perms|600|Private key - SECURITY RISK if too permissive" >> "$temp_issues"
                    issues_found=$((issues_found + 1))
                else
                    echo "   [OK] $(basename "$file"): $current_perms"
                fi
            fi
        done
    else
        echo "   [SKIP] Private key directory not found"
    fi
    echo ""

    # Check 2: tls-crypt-v2 keys must be 600
    echo "2. Checking tls-crypt-v2 keys (*.pem files)..."
    if [ -d "${OVPN_PKI}/private" ]; then
        for file in ${OVPN_PKI}/private/*.pem; do
            if [ -f "$file" ]; then
                current_perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%Lp" "$file" 2>/dev/null)
                if [ "$current_perms" != "600" ] && [ "$current_perms" != "400" ]; then
                    echo "   [ISSUE] $(basename "$file"): $current_perms (should be 600)"
                    echo "$file|$current_perms|600|TLS-Crypt key - SECURITY RISK if too permissive" >> "$temp_issues"
                    issues_found=$((issues_found + 1))
                else
                    echo "   [OK] $(basename "$file"): $current_perms"
                fi
            fi
        done
    fi
    echo ""

    # Check 3: CA certificate should be 644 (world-readable is OK)
    echo "3. Checking CA certificate..."
    if [ -f "${OVPN_PKI}/ca.crt" ]; then
        current_perms=$(stat -c "%a" "${OVPN_PKI}/ca.crt" 2>/dev/null || stat -f "%Lp" "${OVPN_PKI}/ca.crt" 2>/dev/null)
        if [ "$current_perms" != "644" ] && [ "$current_perms" != "600" ] && [ "$current_perms" != "400" ]; then
            echo "   [ISSUE] ca.crt: $current_perms (should be 644)"
            echo "${OVPN_PKI}/ca.crt|$current_perms|644|CA certificate" >> "$temp_issues"
            issues_found=$((issues_found + 1))
        else
            echo "   [OK] ca.crt: $current_perms"
        fi
    else
        echo "   [SKIP] CA certificate not found"
    fi
    echo ""

    # Check 4: Server certificate should be 644
    echo "4. Checking server certificate..."
    if [ -f "${OVPN_PKI}/issued/server.crt" ]; then
        current_perms=$(stat -c "%a" "${OVPN_PKI}/issued/server.crt" 2>/dev/null || stat -f "%Lp" "${OVPN_PKI}/issued/server.crt" 2>/dev/null)
        if [ "$current_perms" != "644" ] && [ "$current_perms" != "600" ] && [ "$current_perms" != "400" ]; then
            echo "   [ISSUE] server.crt: $current_perms (should be 644)"
            echo "${OVPN_PKI}/issued/server.crt|$current_perms|644|Server certificate" >> "$temp_issues"
            issues_found=$((issues_found + 1))
        else
            echo "   [OK] server.crt: $current_perms"
        fi
    else
        echo "   [SKIP] Server certificate not found"
    fi
    echo ""

    # Check 5: DH parameters should be 644
    echo "5. Checking DH parameters..."
    if [ -f "${OVPN_PKI}/dh.pem" ]; then
        current_perms=$(stat -c "%a" "${OVPN_PKI}/dh.pem" 2>/dev/null || stat -f "%Lp" "${OVPN_PKI}/dh.pem" 2>/dev/null)
        if [ "$current_perms" != "644" ] && [ "$current_perms" != "600" ] && [ "$current_perms" != "400" ]; then
            echo "   [ISSUE] dh.pem: $current_perms (should be 644)"
            echo "${OVPN_PKI}/dh.pem|$current_perms|644|DH parameters" >> "$temp_issues"
            issues_found=$((issues_found + 1))
        else
            echo "   [OK] dh.pem: $current_perms"
        fi
    else
        echo "   [SKIP] DH parameters not found"
    fi
    echo ""

    # Check 6: Server config file
    echo "6. Checking server config file..."
    if [ -f "$OVPN_SERVER_CONF" ]; then
        current_perms=$(stat -c "%a" "$OVPN_SERVER_CONF" 2>/dev/null || stat -f "%Lp" "$OVPN_SERVER_CONF" 2>/dev/null)
        if [ "$current_perms" != "644" ] && [ "$current_perms" != "600" ]; then
            echo "   [ISSUE] $(basename "$OVPN_SERVER_CONF"): $current_perms (should be 644)"
            echo "$OVPN_SERVER_CONF|$current_perms|644|Server config file" >> "$temp_issues"
            issues_found=$((issues_found + 1))
        else
            echo "   [OK] $(basename "$OVPN_SERVER_CONF"): $current_perms"
        fi
    else
        echo "   [SKIP] Server config not found"
    fi
    echo ""

    # Check 7: Directory permissions (must be traversable)
    echo "7. Checking directory permissions..."
    for dir in "${OVPN_PKI}" "${OVPN_PKI}/private" "${OVPN_PKI}/issued" "/etc/openvpn"; do
        if [ -d "$dir" ]; then
            current_perms=$(stat -c "%a" "$dir" 2>/dev/null || stat -f "%Lp" "$dir" 2>/dev/null)
            # Directories need at least 755 for nobody:nogroup to traverse
            if [ "$current_perms" != "755" ] && [ "$current_perms" != "750" ] && [ "$current_perms" != "700" ]; then
                echo "   [WARN] $dir: $current_perms (recommend 755 for nobody access)"
                echo "$dir|$current_perms|755|Directory - needs traversal permissions" >> "$temp_issues"
                issues_found=$((issues_found + 1))
            else
                # Check if it's 700 which might block nobody:nogroup
                if [ "$current_perms" = "700" ]; then
                    echo "   [WARN] $dir: $current_perms (may block nobody:nogroup access)"
                else
                    echo "   [OK] $dir: $current_perms"
                fi
            fi
        fi
    done
    echo ""

    # Check 8: Log directory writability for nobody:nogroup
    echo "8. Checking log/run directories for nobody:nogroup access..."
    echo "   Note: Required if OpenVPN runs as 'user nobody / group nogroup'"
    echo ""

    # Check if nobody user exists
    if id nobody >/dev/null 2>&1; then
        echo "   [OK] User 'nobody' exists"
    else
        echo "   [WARN] User 'nobody' does not exist"
    fi

    # Check if nogroup exists
    if getent group nogroup >/dev/null 2>&1 || grep -q "^nogroup:" /etc/group 2>/dev/null; then
        echo "   [OK] Group 'nogroup' exists"
    else
        echo "   [WARN] Group 'nogroup' does not exist"
        echo "          Consider using 'group nobody' instead in server.conf"
    fi
    echo ""

    # Summary
    total_issues=$(wc -l < "$temp_issues" 2>/dev/null || echo "0")
    echo "=========================================="
    if [ "$total_issues" -eq 0 ]; then
        echo "RESULT: All permissions are correctly set!"
        echo ""
        echo "Your OpenVPN installation should not have permission-related issues."
    else
        echo "RESULT: Found $total_issues permission issue(s)"
        echo ""
        echo "Issues found:"
        local counter=1
        while read -r line; do
            filepath=$(echo "$line" | cut -d'|' -f1)
            current=$(echo "$line" | cut -d'|' -f2)
            expected=$(echo "$line" | cut -d'|' -f3)
            description=$(echo "$line" | cut -d'|' -f4)
            echo "  $counter. $filepath"
            echo "     Current: $current | Expected: $expected"
            echo "     Type: $description"
            counter=$((counter + 1))
        done < "$temp_issues"
        echo ""
        echo "These issues may cause:"
        echo "  - OpenVPN to fail to start"
        echo "  - 'Permission denied' errors in logs"
        echo "  - Security vulnerabilities (if private keys are too permissive)"
        echo ""

        read -p "Fix all permission issues now? (yes/no): " fix_all

        if [ "$fix_all" = "yes" ]; then
            echo ""
            echo "Fixing permissions..."
            while read -r line; do
                filepath=$(echo "$line" | cut -d'|' -f1)
                expected=$(echo "$line" | cut -d'|' -f3)
                if chmod "$expected" "$filepath" 2>/dev/null; then
                    echo "  [FIXED] $filepath -> $expected"
                else
                    echo "  [FAILED] Could not change permissions on $filepath"
                fi
            done < "$temp_issues"
            echo ""
            echo "Permission fixes applied!"
            echo ""
            echo "IMPORTANT: If OpenVPN runs as 'user nobody', also ensure:"
            echo "  - /var/log is writable by nobody (or use relative status path)"
            echo "  - /var/run is writable by nobody (or disable --writepid)"
            echo "  - Or comment out 'user nobody' and 'group nogroup' in server.conf"
        else
            echo "No changes made."
            echo ""
            echo "To fix manually, run these commands:"
            while read -r line; do
                filepath=$(echo "$line" | cut -d'|' -f1)
                expected=$(echo "$line" | cut -d'|' -f3)
                echo "  chmod $expected $filepath"
            done < "$temp_issues"
        fi
    fi
    echo "=========================================="
    echo ""

    # Cleanup temp file
    rm -f "$temp_issues"
}

# Clear terminal at startup for clean display
reset

# Main menu
while true; do
    echo ""
    echo "=================================================="
    echo "   OpenWRT OpenVPN Management"
    echo "=================================================="
    echo "Currently managing: [$OVPN_INSTANCE]"
    echo ""
    echo "Instance Management:"
    echo "  i) Select/Create OpenVPN instance"
    echo "  l) List all OpenVPN instances"
    echo ""
    echo "Server Configuration:"
    echo "  0) Auto-Detect server settings"
    echo "  1) Generate/Update server.conf"
    echo "  2) Restore server.conf from backup"
    echo "  3) Toggle IPv6 support (Currently: $OVPN_IPV6_ENABLE)"
    echo "  p) Configure performance (bandwidth limiting)"
    echo ""
    echo "Certificate Management:"
    echo "  4) Create new client certificate"
    echo "  5) List current clients"
    echo "  6) Revoke client certificate"
    echo "  7) Check certificate expiration"
    echo "  8) Renew certificate"
    echo "  9) Show certificate details"
    echo ""
    echo "Configuration Files:"
    echo " 10) Generate all .ovpn config files"
    echo " 11) Generate single .ovpn config file"
    echo ""
    echo "Setup & Integration:"
    echo " 12) Install and initialize EasyRSA for OpenVPN"
    echo " 13) Install LuCI OpenVPN web interface"
    echo ""
    echo "Firewall Management:"
    echo " 14) Check firewall configuration"
    echo " 15) Configure VPN firewall access"
    echo ""
    echo "VPN Monitoring:"
    echo " 16) Monitor VPN address usage (IPv4 & IPv6)"
    echo ""
    echo "Diagnostics:"
    echo " 17) Diagnose IPv6 routing issues"
    echo " 18) Check/Fix file permissions"
    echo ""
    echo " 19) Exit"
    echo ""
    read -p "Select an option: " choice
    
    case $choice in
        i|I)
            select_openvpn_instance
            read -p "Press Enter to continue..."
            ;;
        l|L)
            list_openvpn_instances
            read -p "Press Enter to continue..."
            ;;
	0)
            auto_detect_fqdn
            ;;
        1)
            generate_server_conf
            ;;
        2)
            restore_server_conf
            ;;
        3)
            toggle_ipv6
            read -p "Press Enter to continue..."
            ;;
        p|P)
            configure_performance
            read -p "Press Enter to continue..."
            ;;
        4)
            create_client
            ;;
        5)
            list_clients
            read -p "Press Enter to continue..."
            ;;
        6)
            revoke_client
            ;;
        7)
            check_expiration
            read -p "Press Enter to continue..."
            ;;
        8)
            renew_certificate
            ;;
        9)
            show_cert_details
            read -p "Press Enter to continue..."
            ;;
        10)
            generate_all_ovpn
            read -p "Press Enter to continue..."
            ;;
        11)
            echo ""
            read -p "Enter client name: " client_name
            if [ -n "$client_name" ]; then
                generate_single_ovpn "$client_name"
            else
                echo "Error: No client name provided"
            fi
            read -p "Press Enter to continue..."
            ;;
	    12)
            key_management_first_time
            ;;
        13)
            install_luci_openvpn
            read -p "Press Enter to continue..."
            ;;
        14)
            check_firewall
            read -p "Press Enter to continue..."
            ;;
        15)
            configure_vpn_firewall
            read -p "Press Enter to continue..."
            ;;
        16)
            monitor_vpn_usage
            read -p "Press Enter to continue..."
            ;;
        17)
            diagnose_ipv6_routing
            read -p "Press Enter to continue..."
            ;;
        18)
            check_fix_permissions
            read -p "Press Enter to continue..."
            ;;
        19)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
done