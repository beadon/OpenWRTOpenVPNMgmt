# ShellSpec integration tests for PKI initialization (Menu option 12)
# Requires Docker container running

Include spec/spec_helper.sh

Describe "PKI Initialization (Menu option 12)"
    # Skip if Docker not available
    Skip if "Docker not available" ! command -v docker >/dev/null 2>&1

    # Validation helper: check file contains valid X.509 certificate
    valid_x509_cert() {
        docker_exec cat "$1" 2>/dev/null | grep -q "BEGIN CERTIFICATE" &&
        docker_exec cat "$1" 2>/dev/null | grep -q "END CERTIFICATE"
    }

    # Validation helper: check file contains valid private key
    valid_private_key() {
        docker_exec cat "$1" 2>/dev/null | grep -q "BEGIN.*PRIVATE KEY" &&
        docker_exec cat "$1" 2>/dev/null | grep -q "END.*PRIVATE KEY"
    }

    # Validation helper: check DH parameters file is valid
    valid_dh_params() {
        docker_exec cat "$1" 2>/dev/null | grep -q "BEGIN DH PARAMETERS" &&
        docker_exec cat "$1" 2>/dev/null | grep -q "END DH PARAMETERS"
    }

    # Validation helper: check file permissions are restrictive (600 or 400)
    restrictive_perms() {
        perms=$(docker_exec stat -c '%a' "$1" 2>/dev/null)
        [ "$perms" = "600" ] || [ "$perms" = "400" ]
    }

    setup_container() {
        stop_container
        start_container
        copy_script_to_container
        # Install dependencies
        docker_exec opkg update >/dev/null 2>&1
        docker_exec opkg install openvpn-openssl openvpn-easy-rsa >/dev/null 2>&1
    }

    run_pki_init() {
        # Run menu option 12 - PKI initialization
        # This takes time due to DH parameter generation
        printf '12\n19\n' | docker_exec /root/openvpn_server_management.sh >/dev/null 2>&1
    }

    BeforeAll 'setup_container'
    AfterAll 'stop_container'

    Describe "key_management_first_time()"
        BeforeAll 'run_pki_init'

        It "creates PKI directory structure"
            When call docker_exec test -d /etc/easy-rsa/pki
            The status should be success
        End

        It "creates CA certificate file"
            When call docker_exec test -f /etc/easy-rsa/pki/ca.crt
            The status should be success
        End

        It "CA certificate is valid X.509 format"
            When call valid_x509_cert /etc/easy-rsa/pki/ca.crt
            The status should be success
        End

        It "creates server certificate file"
            When call docker_exec test -f /etc/easy-rsa/pki/issued/server.crt
            The status should be success
        End

        It "server certificate is valid X.509 format"
            When call valid_x509_cert /etc/easy-rsa/pki/issued/server.crt
            The status should be success
        End

        It "creates server private key file"
            When call docker_exec test -f /etc/easy-rsa/pki/private/server.key
            The status should be success
        End

        It "server private key is valid format"
            When call valid_private_key /etc/easy-rsa/pki/private/server.key
            The status should be success
        End

        It "creates DH parameters file"
            When call docker_exec test -f /etc/easy-rsa/pki/dh.pem
            The status should be success
        End

        It "DH parameters file is valid format"
            When call valid_dh_params /etc/easy-rsa/pki/dh.pem
            The status should be success
        End

        It "creates TLS-Crypt server key file"
            When call docker_exec test -f /etc/easy-rsa/pki/private/server.pem
            The status should be success
        End

        It "private key files have restrictive permissions"
            When call restrictive_perms /etc/easy-rsa/pki/private/server.key
            The status should be success
        End
    End
End
