#!/bin/sh

# Configuration parameters
OVPN_PKI="/etc/easy-rsa/pki"
OVPN_DIR="/root/ovpn_config_out"
OVPN_SERVER_CONF="/etc/openvpn/server.conf"
OVPN_SERVER_BACKUP="/etc/openvpn/server.conf.BAK"
export EASYRSA_PKI="${OVPN_PKI}"
export EASYRSA_BATCH="1"

# OpenVPN server configuration - EDIT THESE VALUES
OVPN_SERV="vpn.example.com"  # Your VPN server address
OVPN_PORT="1194"              # VPN port
OVPN_PROTO="udp"              # Protocol: udp or tcp
OVPN_POOL="10.8.0.0 255.255.255.0"  # VPN subnet

# IPv6 configuration - EDIT THESE VALUES
OVPN_IPV6_ENABLE="yes"        # Enable IPv6: yes or no
# Use Unique Local Address (ULA) - Generate random at https://unique-local-ipv6.com/
# Format: fdXX:XXXX:XXXX::/48 then use /64 subnet from that
OVPN_IPV6_POOL="fd42:4242:4242:1194::/64"  # IPv6 VPN subnet (ULA recommended)

# Auto-detect DNS and domain from OpenWrt UCI
OVPN_DNS="${OVPN_POOL%.* *}.1"
OVPN_DOMAIN=$(uci get dhcp.@dnsmasq[0].domain 2>/dev/null || echo "lan")

# Auto-detect IPv6 DNS (first address in IPv6 pool)
OVPN_IPV6_DNS="${OVPN_IPV6_POOL%::*}::1"

# Auto-Detect DDNS configured name, Fetch server address configured elsewhere
auto_detect_fqdn() {

    echo ""
    echo "Current script-default settings:"
    echo "  Port: $OVPN_PORT"
    echo "  Protocol: $OVPN_PROTO"
    echo "  IPv4 VPN Subnet: $OVPN_POOL"
    echo "  IPv4 DNS Server: $OVPN_DNS"
    echo "  IPv6 Enabled: $OVPN_IPV6_ENABLE"
    echo "  IPv6 VPN Subnet: $OVPN_IPV6_POOL"
    echo "  IPv6 DNS Server: $OVPN_IPV6_DNS"
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
            echo "  IPv6 enabled"
        else
            # Check if IPv6 is explicitly disabled
            if grep -q "^#.*server-ipv6" "$OVPN_SERVER_CONF"; then
                OVPN_IPV6_ENABLE="no"
                echo "  IPv6 is disabled in server.conf"
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
    echo "=== Final Auto-Detected Settings ==="
    echo "  Port: $OVPN_PORT"
    echo "  Protocol: $OVPN_PROTO"
    echo "  IPv4 VPN Subnet: $OVPN_POOL"
    echo "  IPv4 DNS Server: $OVPN_DNS"
    echo "  IPv6 Enabled: $OVPN_IPV6_ENABLE"
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "  IPv6 VPN Subnet: $OVPN_IPV6_POOL"
        echo "  IPv6 DNS Server: $OVPN_IPV6_DNS"
    fi
    echo "  Domain: $OVPN_DOMAIN"
    echo "  VPN Server: $OVPN_SERV"
    echo ""

}

# Ensure output directory exists
if [ ! -d "$OVPN_DIR" ]; then
    mkdir -p "$OVPN_DIR"
fi

# Function to configure VPN firewall zones
configure_vpn_firewall() {
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

    # Rename zones for easier reference (if not already named)
    uci rename firewall.@zone[0]="lan" 2>/dev/null
    uci rename firewall.@zone[1]="wan" 2>/dev/null

    # Remove tun+ from LAN zone if it exists, then add it fresh
    uci del_list firewall.lan.device="tun+" 2>/dev/null
    uci add_list firewall.lan.device="tun+"

    echo "  Added tun+ interface to LAN zone"

    # Delete existing OpenVPN rule if present, then create fresh
    uci -q delete firewall.ovpn
    uci set firewall.ovpn="rule"
    uci set firewall.ovpn.name="Allow-OpenVPN"
    uci set firewall.ovpn.src="wan"
    uci set firewall.ovpn.dest_port="${OVPN_PORT}"
    uci set firewall.ovpn.proto="${OVPN_PROTO}"
    uci set firewall.ovpn.target="ACCEPT"
    uci set firewall.ovpn.family="any"

    echo "  Created OpenVPN WAN access rule (IPv4 & IPv6)"

    # Enable IPv6 forwarding if IPv6 is enabled
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        # Check if IPv6 forwarding is enabled
        ipv6_forward=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo "0")
        if [ "$ipv6_forward" != "1" ]; then
            echo "  Enabling IPv6 forwarding..."
            sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

            # Make it persistent
            if ! grep -q "net.ipv6.conf.all.forwarding" /etc/sysctl.conf 2>/dev/null; then
                echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
                echo "  IPv6 forwarding enabled (persistent)"
            fi
        else
            echo "  IPv6 forwarding already enabled"
        fi
    fi

    # Commit changes
    uci commit firewall

    echo ""
    echo "Firewall configuration updated"
    echo ""

    read -p "Restart firewall to apply changes? (y/n): " restart
    if [ "$restart" = "y" ] || [ "$restart" = "Y" ]; then
        service firewall restart
        echo "Firewall restarted"
        echo ""
        echo "VPN clients will now have full LAN access"
        if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
            echo "IPv6 routing enabled for VPN clients"
        fi
    else
        echo "Remember to restart firewall: service firewall restart"
    fi

    echo ""
}

# Function to check if OpenVPN port is open in firewall and VPN zone configuration
check_firewall() {
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
        echo "   To add VPN interface to LAN zone, use option 14"
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
    echo "=== Summary ==="
    echo ""
    
    if [ $vpn_in_lan -eq 1 ] && [ $port_open -eq 1 ]; then
        echo "  Firewall is properly configured for OpenVPN"
    else
        echo "  Firewall configuration incomplete"
        echo "  Use option 14 to automatically configure firewall"
    fi
    
    echo ""
}

# Function to generate/update server.conf
generate_server_conf() {
    echo ""
    echo "=== Generate/Update OpenVPN Server Configuration ==="
    echo ""
    echo "Current settings:"
    echo "  Port: $OVPN_PORT"
    echo "  Protocol: $OVPN_PROTO"
    echo "  IPv4 VPN Subnet: $OVPN_POOL"
    echo "  IPv4 DNS Server: $OVPN_DNS"
    echo "  IPv6 Enabled: $OVPN_IPV6_ENABLE"
    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "  IPv6 VPN Subnet: $OVPN_IPV6_POOL"
        echo "  IPv6 DNS Server: $OVPN_IPV6_DNS"
    fi
    echo "  Domain: $OVPN_DOMAIN"
    echo ""
    
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
        cat << EOF >> ${OVPN_SERVER_CONF}
# IPv6 configuration
server-ipv6 ${OVPN_IPV6_POOL}

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

# Certificate Revocation List (uncomment after first revocation)
# crl-verify ${OVPN_PKI}/crl.pem
EOF
    
    echo ""
    echo "Server configuration created: $OVPN_SERVER_CONF"
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
    
    read -p "Restart OpenVPN daemon to apply changes? (y/n): " restart
    if [ "$restart" = "y" ] || [ "$restart" = "Y" ]; then
        /etc/init.d/openvpn restart
        echo "OpenVPN daemon restarted"
    else
        echo "Remember to restart OpenVPN daemon: /etc/init.d/openvpn restart"
    fi
}

# Function to restore server.conf from backup
restore_server_conf() {
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
    OVPN_ID="$1"
    
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

# Function to toggle IPv6 configuration
toggle_ipv6() {
    echo ""
    echo "=== IPv6 Configuration ==="
    echo ""
    echo "Current IPv6 status: $OVPN_IPV6_ENABLE"
    echo ""

    if [ "$OVPN_IPV6_ENABLE" = "yes" ]; then
        echo "IPv6 is currently ENABLED"
        echo "  IPv6 VPN Subnet: $OVPN_IPV6_POOL"
        echo "  IPv6 DNS Server: $OVPN_IPV6_DNS"
        echo ""
        read -p "Disable IPv6 support? (yes/no): " confirm

        if [ "$confirm" = "yes" ]; then
            OVPN_IPV6_ENABLE="no"
            echo ""
            echo "IPv6 support disabled"
            echo "Note: Regenerate server.conf (option 1) to apply changes"
        else
            echo "No changes made"
        fi
    else
        echo "IPv6 is currently DISABLED"
        echo ""
        echo "Enabling IPv6 will:"
        echo "  1. Add IPv6 subnet to VPN tunnel"
        echo "  2. Push IPv6 routes to clients"
        echo "  3. Enable IPv6 DNS for VPN clients"
        echo ""
        echo "Recommended: Use ULA (Unique Local Address) for private IPv6"
        echo "Generate random ULA at: https://unique-local-ipv6.com/"
        echo ""
        read -p "Enable IPv6 support? (yes/no): " confirm

        if [ "$confirm" = "yes" ]; then
            echo ""
            echo "Current IPv6 subnet: $OVPN_IPV6_POOL"
            read -p "Enter IPv6 subnet (or press Enter to keep current): " new_ipv6_pool

            if [ -n "$new_ipv6_pool" ]; then
                OVPN_IPV6_POOL="$new_ipv6_pool"
                OVPN_IPV6_DNS="${OVPN_IPV6_POOL%::*}::1"
            fi

            OVPN_IPV6_ENABLE="yes"
            echo ""
            echo "IPv6 support enabled"
            echo "  IPv6 VPN Subnet: $OVPN_IPV6_POOL"
            echo "  IPv6 DNS Server: $OVPN_IPV6_DNS"
            echo ""
            echo "Note: Regenerate server.conf (option 1) to apply changes"
        else
            echo "No changes made"
        fi
    fi

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

# Main menu
while true; do
    echo ""
    echo "=================================================="
    echo "   OpenWRT OpenVPN Management"
    echo "=================================================="
    echo "Server Configuration:"
    echo "  0) Auto-Detect server settings"
    echo "  1) Generate/Update server.conf"
    echo "  2) Restore server.conf from backup"
    echo "  3) Toggle IPv6 support (Currently: $OVPN_IPV6_ENABLE)"
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
    echo "EasyRSA Management:"
    echo " 12) Install and initialize EasyRSA for OpenVPN"
    echo ""
    echo "Firewall Management:"
    echo " 13) Check firewall configuration"
    echo " 14) Configure VPN firewall access"
    echo ""
    echo " 15) Exit"
    echo ""
    read -p "Select an option (0-15): " choice
    
    case $choice in
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
            check_firewall
            read -p "Press Enter to continue..."
            ;;
        14)
            configure_vpn_firewall
            read -p "Press Enter to continue..."
            ;;
        15)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please select 0-15."
            ;;
    esac
done