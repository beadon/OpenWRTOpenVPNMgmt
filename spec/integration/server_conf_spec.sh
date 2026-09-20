# ShellSpec integration tests for server configuration generation
# Requires Docker container with PKI already initialized

Include spec/spec_helper.sh

Describe "Server Configuration (Menu option 1)"
    # Skip if Docker not available
    Skip if "Docker not available" ! command -v docker >/dev/null 2>&1

    # Validation helper: check port is valid (1-65535)
    valid_port() {
        port="$1"
        [ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null
    }

    # Validation helper: check IPv4 octet is valid (0-255)
    valid_octet() {
        octet="$1"
        [ "$octet" -ge 0 ] 2>/dev/null && [ "$octet" -le 255 ] 2>/dev/null
    }

    # Validation helper: check IPv4 address is valid
    valid_ipv4() {
        echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
        IFS='.' read -r o1 o2 o3 o4 <<EOF
$1
EOF
        valid_octet "$o1" && valid_octet "$o2" && valid_octet "$o3" && valid_octet "$o4"
    }

    # Validation helper: extract and validate port from config
    extract_port() {
        grep -E '^port [0-9]+' /tmp/server_conf_test | awk '{print $2}'
    }

    # Validation helper: extract and validate server IP from config
    extract_server_ip() {
        grep -E '^server [0-9]' /tmp/server_conf_test | awk '{print $2}'
    }

    Describe "Generate server.conf"
        setup() {
            # Generate config and cache for tests
            printf '1\n\nyes\nn\nn\n19\n' | docker_exec /root/openvpn_server_management.sh >/dev/null 2>&1
            docker_exec cat /etc/openvpn/server.conf > /tmp/server_conf_test 2>/dev/null
        }

        BeforeAll 'setup'

        It "creates server.conf file"
            When call docker_exec test -f /etc/openvpn/server.conf
            The status should be success
        End

        It "contains valid port number (1-65535)"
            port=$(extract_port)
            When call valid_port "$port"
            The status should be success
        End

        It "contains valid protocol (udp or tcp)"
            result=$(grep -E '^proto (udp|tcp)' /tmp/server_conf_test)
            When call test -n "$result"
            The status should be success
        End

        It "contains valid server IPv4 address"
            ip=$(extract_server_ip)
            When call valid_ipv4 "$ip"
            The status should be success
        End

        It "contains valid subnet mask"
            mask=$(grep -E '^server [0-9]' /tmp/server_conf_test | awk '{print $3}')
            When call valid_ipv4 "$mask"
            The status should be success
        End

        It "references existing CA certificate file"
            ca_path=$(grep -E '^ca ' /tmp/server_conf_test | awk '{print $2}')
            When call docker_exec test -f "$ca_path"
            The status should be success
        End

        It "references existing server certificate file"
            cert_path=$(grep -E '^cert ' /tmp/server_conf_test | awk '{print $2}')
            When call docker_exec test -f "$cert_path"
            The status should be success
        End

        It "references existing server key file"
            key_path=$(grep -E '^key ' /tmp/server_conf_test | awk '{print $2}')
            When call docker_exec test -f "$key_path"
            The status should be success
        End

        It "references existing DH parameters file"
            dh_path=$(grep -E '^dh ' /tmp/server_conf_test | awk '{print $2}')
            When call docker_exec test -f "$dh_path"
            The status should be success
        End
    End

    Describe "Backup functionality"
        It "creates backup file when config exists"
            # Generate again to trigger backup
            printf '1\n\nyes\nn\nn\n19\n' | docker_exec /root/openvpn_server_management.sh >/dev/null 2>&1
            When call docker_exec test -f /etc/openvpn/server.conf.bak
            The status should be success
        End
    End
End
