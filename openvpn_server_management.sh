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

# Auto-detect DNS and domain from OpenWrt UCI
OVPN_DNS="${OVPN_POOL%.* *}.1"
OVPN_DOMAIN=$(uci get dhcp.@dnsmasq[0].domain 2>/dev/null || echo "lan")

# Auto-Detect DDNS configured name, Fetch server address configured elsewhere
auto_detect_fqdn() {

    echo ""                                      
    echo "Active script-selected server settings:"                     
    echo "  Port: $OVPN_PORT"                    
    echo "  Protocol: $OVPN_PROTO"               
    echo "  VPN Subnet: $OVPN_POOL"              
    echo "  DNS Server: $OVPN_DNS"
    echo "  Domain: $OVPN_DOMAIN"                
    echo "  VPN Server: $OVPN_SERV"
    echo "  VPN Pool: $OVPN_POOL"
    echo ""                                      

    NET_FQDN="$(uci -q get ddns.@service[0].lookup_host)"
    . /lib/functions/network.sh
    network_flush_cache
    network_find_wan NET_IF
    network_get_ipaddr NET_ADDR "${NET_IF}"
    if [ -n "${NET_FQDN}" ]
    then OVPN_SERV="${NET_FQDN}"
    else OVPN_SERV="${NET_ADDR}"
    fi

    echo ""                                      
    echo "Auto-Detected server settings:"                     
    echo "  Port: $OVPN_PORT"                    
    echo "  Protocol: $OVPN_PROTO"               
    echo "  VPN Subnet: $OVPN_POOL"              
    echo "  DNS Server: $OVPN_DNS"
    echo "  Domain: $OVPN_DOMAIN"                
    echo "  VPN Server: $OVPN_SERV"
    echo "  VPN Pool: $OVPN_POOL"
    echo ""                                      

}

# Ensure output directory exists
if [ ! -d "$OVPN_DIR" ]; then
    mkdir -p "$OVPN_DIR"
fi

# Function to check if OpenVPN port is open in firewall
check_firewall() {
    echo ""
    echo "=== Checking Firewall Configuration ==="
    echo ""
    echo "Checking for OpenVPN port ${OVPN_PORT}/${OVPN_PROTO} on WAN..."
    echo ""
    
    # Check if firewall config exists
    if ! uci show firewall >/dev/null 2>&1; then
        echo "WARNING: Cannot access firewall configuration"
        echo "Firewall may not be configured or UCI is not available"
        return 1
    fi
    
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
                echo "  Firewall rule found: $rule_name"
                echo "  Port ${OVPN_PORT}/${OVPN_PROTO} is OPEN on WAN"
                break
            fi
        fi
        
        rule_index=$((rule_index + 1))
    done
    
    if [ $port_open -eq 0 ]; then
        echo " WARNING: No firewall rule found!"
        echo ""
        echo "OpenVPN port ${OVPN_PORT}/${OVPN_PROTO} does not appear to be open on WAN."
        echo ""
        echo "To open the port, run these commands:"
        echo ""
        echo "  uci add firewall rule"
        echo "  uci set firewall.@rule[-1].name='Allow-OpenVPN'"
        echo "  uci set firewall.@rule[-1].src='wan'"
        echo "  uci set firewall.@rule[-1].dest_port='${OVPN_PORT}'"
        echo "  uci set firewall.@rule[-1].proto='${OVPN_PROTO}'"
        echo "  uci set firewall.@rule[-1].target='ACCEPT'"
        echo "  uci commit firewall"
        echo "  service firewall restart"
        echo ""
        read -p "Would you like to add this firewall rule now? (y/n): " add_rule
        
        if [ "$add_rule" = "y" ] || [ "$add_rule" = "Y" ]; then
            echo ""
            echo "Adding firewall rule..."
            uci add firewall rule
            uci set firewall.@rule[-1].name='Allow-OpenVPN'
            uci set firewall.@rule[-1].src='wan'
            uci set firewall.@rule[-1].dest_port="${OVPN_PORT}"
            uci set firewall.@rule[-1].proto="${OVPN_PROTO}"
            uci set firewall.@rule[-1].target='ACCEPT'
            uci commit firewall
            service firewall restart
            
            echo "✓ Firewall rule added and applied"
        else
            echo "Firewall rule not added. Remember to open port ${OVPN_PORT}/${OVPN_PROTO} manually."
        fi
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
    echo "  VPN Subnet: $OVPN_POOL"
    echo "  DNS Server: $OVPN_DNS"
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
# Generated by manage_openvpn_keys.sh

# Network settings
port ${OVPN_PORT}
proto ${OVPN_PROTO}
dev tun

# Server mode and VPN subnet
server ${OVPN_POOL}
topology subnet

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

# Push routes and DNS to clients
push "redirect-gateway def1"
push "dhcp-option DNS ${OVPN_DNS}"
push "dhcp-option DOMAIN ${OVPN_DOMAIN}"
push "persist-tun"
push "persist-key"

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
    echo "   OpenVPN Key Management"
    echo "=================================================="
    echo "Server Configuration:"
    echo "  0) Auto-Detect server settings"
    echo "  1) Generate/Update server.conf"
    echo "  2) Restore server.conf from backup"
    echo "  3) Check firewall configuration"
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
    echo " 13) Exit"
    echo ""
    read -p "Select an option (0-13): " choice
    
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
            check_firewall
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
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please select 0-13."
            ;;
    esac
done
