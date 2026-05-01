#!/bin/sh
# Integration test suite — runs ON the OpenWrt device, drives the interactive
# menu via sexpect. Invoked remotely by run_tests.sh on the Mac.
#
# Usage (from Mac):
#   OPENWRT_HOST=192.168.88.32 ./tests/run_tests.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/sexpect_helper.sh"

OVPN_EASYRSA="/etc/easy-rsa"
OVPN_PKI="/etc/easy-rsa/pki"
OVPN_CONF="/etc/openvpn/server.conf"
OVPN_DIR="/root/ovpn_config_out"
CRONTAB="/etc/crontabs/root"
TEST_CLIENT="testclient1"

PASS=0
FAIL=0

# ── Test framework ────────────────────────────────────────────────────────────

TEST_NAME=""
ts() { date +%H:%M:%S; }
it() { TEST_NAME="$1"; }

pass() {
    printf "  [%s] PASS: %s\n" "$(ts)" "$TEST_NAME"
    PASS=$((PASS + 1))
}

fail() {
    printf "  [%s] FAIL: %s — %s\n" "$(ts)" "$TEST_NAME" "$1" >&2
    FAIL=$((FAIL + 1))
}

check() {
    if "$@" 2>/dev/null; then pass; else fail "$*"; fi
}

# ── Setup / teardown ──────────────────────────────────────────────────────────

cleanup() {
    kill_session 2>/dev/null || true
    rm -rf "$OVPN_EASYRSA" "$OVPN_CONF" "$CRONTAB" "$OVPN_DIR" 2>/dev/null || true
}

trap cleanup EXIT INT TERM
cleanup
mkdir -p "$OVPN_EASYRSA" "$(dirname "$OVPN_CONF")"

printf "\n=== OpenVPN Management Script Integration Tests ===\n"
printf "    Started: %s\n\n" "$(ts)"

spawn_script

# ── Suite 1: PKI Initialization (EC / prime256v1) ────────────────────────────

printf "--- [%s] Suite 1: PKI Initialization ---\n" "$(ts)"

it "option 12 completes PKI init"
select_option "12"
check wait_for "Select an option:" 60

it "PKI directory created"
check assert_file_exists "$OVPN_PKI"

it "CA certificate created"
check assert_file_exists "$OVPN_PKI/ca.crt"

it "CA certificate is valid X.509"
check assert_valid_cert "$OVPN_PKI/ca.crt"

it "CA uses EC key (prime256v1)"
if openssl x509 -in "$OVPN_PKI/ca.crt" -noout -text 2>/dev/null | grep -q "id-ecPublicKey"; then
    pass
else
    fail "CA cert is not EC"
fi

it "server certificate created"
check assert_file_exists "$OVPN_PKI/issued/server.crt"

it "server certificate is valid X.509"
check assert_valid_cert "$OVPN_PKI/issued/server.crt"

it "server private key created"
check assert_file_exists "$OVPN_PKI/private/server.key"

it "TLS-crypt-v2 server key created"
check assert_file_exists "$OVPN_PKI/private/server.pem"

it "server private key has 600 permissions"
check assert_file_perms "$OVPN_PKI/private/server.key" "600"

it "no dh.pem (EC skips gen-dh)"
if test -f "$OVPN_PKI/dh.pem"; then
    fail "dh.pem should not exist for EC"
else
    pass
fi

# ── Suite 2: Server Config Generation (option 1) ─────────────────────────────

printf "\n--- [%s] Suite 2: Server Config Generation ---\n" "$(ts)"

it "option 1 generates server.conf"
select_option "1"
expect_send "Press Enter" ""    5   # IPv6 leak warning gate
expect_send "Continue" "y"     10  # new conf: Continue? (y/n)
expect_send "[Vv]iew" "n"      15  # View generated config? (y/n)
expect_send "Restart" "n"      5   # Restart OpenVPN? (y/n)
check wait_for "Select an option:" 5

it "server.conf file created"
check assert_file_exists "$OVPN_CONF"

it "server.conf has tls-version-min 1.2"
check assert_file_contains "$OVPN_CONF" "tls-version-min 1.2"

it "server.conf has AES-256-GCM cipher"
check assert_file_contains "$OVPN_CONF" "AES-256-GCM"

it "server.conf uses 'dh none' (EC)"
check assert_file_contains "$OVPN_CONF" "dh none"

it "server.conf has tls-crypt-v2"
check assert_file_contains "$OVPN_CONF" "tls-crypt-v2"

# ── Suite 3: Client Certificate Creation (option 4) ──────────────────────────

printf "\n--- [%s] Suite 3: Client Certificate Creation ---\n" "$(ts)"

it "option 4 creates client certificate"
select_option "4"
expect_send "Enter client name:" "$TEST_CLIENT" 5
expect_send "Generate" "y"                      10  # Generate .ovpn config file?
expect_send "Daemon restart" "n"                10  # OpenVPN Daemon restart
check wait_for "Select an option:" 10

it "client certificate file created"
check assert_file_exists "$OVPN_PKI/issued/$TEST_CLIENT.crt"

it "client certificate is valid X.509"
check assert_valid_cert "$OVPN_PKI/issued/$TEST_CLIENT.crt"

it "client private key created"
check assert_file_exists "$OVPN_PKI/private/$TEST_CLIENT.key"

it "client private key has 600 permissions"
check assert_file_perms "$OVPN_PKI/private/$TEST_CLIENT.key" "600"

OVPN_PROFILE="$OVPN_DIR/$TEST_CLIENT.ovpn"

it ".ovpn profile created"
check assert_file_exists "$OVPN_PROFILE"

it ".ovpn profile contains inline CA block"
check assert_file_contains "$OVPN_PROFILE" "<ca>"

it ".ovpn profile contains inline tls-crypt-v2 block"
check assert_file_contains "$OVPN_PROFILE" "<tls-crypt-v2>"

# ── Suite 4: CRL — Revoke + Auto-renewal ─────────────────────────────────────

printf "\n--- [%s] Suite 4: CRL Revocation and Auto-renewal ---\n" "$(ts)"

it "option 6 revokes client"
select_option "6"
expect_send "Enter client name to revoke:" "$TEST_CLIENT" 5
expect_send "Are you sure" "yes"                           5
expect_send "Restart" "n"                                  10
check wait_for "Select an option:" 10

it "CRL file created after revocation"
check assert_file_exists "$OVPN_PKI/crl.pem"

it "server.conf has crl-verify (auto-enabled)"
check assert_file_contains "$OVPN_CONF" "crl-verify"

it "revoked client appears in CRL"
if openssl crl -in "$OVPN_PKI/crl.pem" -noout -text 2>/dev/null | grep -q "Revoked"; then
    pass
else
    fail "client not found in CRL"
fi

it "CRL check expiry (r → 1)"
select_option "r"
expect_send "Select option:" "1" 5
expect_send "Press Enter" ""    10  # consume continue gate
check wait_for "Select an option:" 5

it "CRL install cron job (r → 4)"
select_option "r"
expect_send "Select option:" "4" 5
expect_send "Press Enter" ""    10
check wait_for "Select an option:" 5

it "cron job installed in /etc/crontabs/root"
check assert_file_contains "$CRONTAB" "openvpn-crl-renewal"

it "CRL cron status shows installed (r → 3)"
select_option "r"
expect_send "Select option:" "3" 5
expect_send "Press Enter" ""    10
check wait_for "Select an option:" 5

# ── Done ──────────────────────────────────────────────────────────────────────

quit_script
kill_session

printf "\n=== Results: %d passed, %d failed (finished: %s) ===\n\n" "$PASS" "$FAIL" "$(ts)"

[ "$FAIL" -eq 0 ]
