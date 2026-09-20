# ShellSpec integration tests for client certificate operations
# Requires Docker container with PKI already initialized

Include spec/spec_helper.sh

Describe "Client Certificate Operations"
    # Skip if Docker not available
    Skip if "Docker not available" ! command -v docker >/dev/null 2>&1

    # Validation helper: check file contains valid X.509 certificate
    valid_x509_cert() {
        echo "$1" | grep -q "BEGIN CERTIFICATE" && echo "$1" | grep -q "END CERTIFICATE"
    }

    # Validation helper: check file contains valid private key
    valid_private_key() {
        echo "$1" | grep -q "BEGIN.*PRIVATE KEY" && echo "$1" | grep -q "END.*PRIVATE KEY"
    }

    # Validation helper: check ovpn has required sections
    valid_ovpn_structure() {
        file_content="$1"
        echo "$file_content" | grep -q "<ca>" &&
        echo "$file_content" | grep -q "</ca>" &&
        echo "$file_content" | grep -q "<cert>" &&
        echo "$file_content" | grep -q "</cert>" &&
        echo "$file_content" | grep -q "<key>" &&
        echo "$file_content" | grep -q "</key>"
    }

    # Validation helper: check ovpn remote line has valid format
    valid_ovpn_remote() {
        # Format: remote <host> <port> <proto>
        # Port must be 1-65535
        echo "$1" | grep -qE '^remote [^ ]+ [0-9]+ (udp|tcp)'
    }

    Describe "Create client certificate (Menu option 4)"
        setup() {
            printf '4\ntestclient\nn\nn\n19\n' | docker_exec /root/openvpn_server_management.sh >/dev/null 2>&1
        }

        BeforeAll 'setup'

        It "creates client certificate file"
            When call docker_exec test -f /etc/easy-rsa/pki/issued/testclient.crt
            The status should be success
        End

        It "client certificate is valid X.509 format"
            cert_content=$(docker_exec cat /etc/easy-rsa/pki/issued/testclient.crt)
            When call valid_x509_cert "$cert_content"
            The status should be success
        End

        It "creates client private key file"
            When call docker_exec test -f /etc/easy-rsa/pki/private/testclient.key
            The status should be success
        End

        It "client private key is valid format"
            key_content=$(docker_exec cat /etc/easy-rsa/pki/private/testclient.key)
            When call valid_private_key "$key_content"
            The status should be success
        End

        It "creates client TLS-Crypt key file"
            When call docker_exec test -f /etc/easy-rsa/pki/private/testclient.pem
            The status should be success
        End

        It "client key file has restrictive permissions"
            # Key files should be 600 or 400
            perms=$(docker_exec stat -c '%a' /etc/easy-rsa/pki/private/testclient.key 2>/dev/null || \
                    docker_exec stat -f '%Lp' /etc/easy-rsa/pki/private/testclient.key 2>/dev/null)
            When call test "$perms" = "600" -o "$perms" = "400"
            The status should be success
        End
    End

    Describe "Generate .ovpn file (Menu option 11)"
        setup() {
            printf '11\ntestclient\n19\n' | docker_exec /root/openvpn_server_management.sh >/dev/null 2>&1
            docker_exec cat /root/ovpn_config_out/testclient.ovpn > /tmp/ovpn_test 2>/dev/null
        }

        BeforeAll 'setup'

        It "creates ovpn file"
            When call docker_exec test -f /root/ovpn_config_out/testclient.ovpn
            The status should be success
        End

        It "ovpn file has valid structure with required sections"
            ovpn_content=$(cat /tmp/ovpn_test)
            When call valid_ovpn_structure "$ovpn_content"
            The status should be success
        End

        It "ovpn file contains embedded CA certificate"
            ovpn_content=$(cat /tmp/ovpn_test)
            # Extract CA section and validate
            ca_section=$(echo "$ovpn_content" | sed -n '/<ca>/,/<\/ca>/p')
            When call valid_x509_cert "$ca_section"
            The status should be success
        End

        It "ovpn file contains embedded client certificate"
            ovpn_content=$(cat /tmp/ovpn_test)
            cert_section=$(echo "$ovpn_content" | sed -n '/<cert>/,/<\/cert>/p')
            When call valid_x509_cert "$cert_section"
            The status should be success
        End

        It "ovpn file contains TLS-Crypt-v2 key section"
            ovpn_content=$(cat /tmp/ovpn_test)
            When call echo "$ovpn_content"
            The output should include "<tls-crypt-v2>"
            The output should include "</tls-crypt-v2>"
        End
    End

    Describe "List clients (Menu option 5)"
        It "lists created client"
            result=$(printf '5\n19\n' | docker_exec /root/openvpn_server_management.sh 2>&1)

            When call echo "$result"
            The output should include "testclient"
        End
    End
End
