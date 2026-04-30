#!/bin/sh
# Integration test suite — runs ON the OpenWrt device, drives the interactive
# menu via sexpect. Invoked remotely by run_tests.sh on the Mac.
#
# Usage (direct, on device):
#   /root/integration_test.sh
#
# Usage (from Mac via run_tests.sh):
#   OPENWRT_HOST=192.168.88.32 ./tests/run_tests.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/sexpect_helper.sh"

OVPN_PKI="/etc/openvpn/easy-rsa/pki"
OVPN_CONF="/etc/openvpn/server.conf"
TEST_CLIENT="testclient1"

PASS=0
FAIL=0

# ── Test framework ────────────────────────────────────────────────────────────

TEST_NAME=""

it() { TEST_NAME="$1"; }

pass() {
    printf "  PASS: %s\n" "$TEST_NAME"
    PASS=$((PASS + 1))
}

fail() {
    printf "  FAIL: %s — %s\n" "$TEST_NAME" "$1" >&2
    FAIL=$((FAIL + 1))
}

check() {
    if "$@" 2>/dev/null; then pass; else fail "$*"; fi
}

# ── Setup / teardown ──────────────────────────────────────────────────────────

cleanup() {
    kill_session 2>/dev/null || true
    rm -rf "$OVPN_PKI" /etc/openvpn/easy-rsa /etc/openvpn/server.conf \
           /etc/crontabs/root 2>/dev/null || true
}

trap cleanup EXIT INT TERM
cleanup

echo ""
echo "=== OpenVPN Management Script Integration Tests ==="
echo ""

spawn_script

# ── Suite 1: PKI Initialization (EC / prime256v1) ────────────────────────────

echo "--- Suite 1: PKI Initialization ---"

it "menu appears on startup"
check wait_for "$MENU_PROMPT" 15

it "option 12 completes PKI init"
select_option "12"
check wait_for "$MENU_PROMPT" 120

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

echo ""
echo "--- Suite 2: Server Config Generation ---"

it "option 1 generates server.conf"
select_option "1"
wait_for "overwrite\? \(yes/no\)" 15 && send "yes" || true
wait_for "view.*\(y/n\)" 15 && send "n" || true
wait_for "Restart OpenVPN.*\(y/n\)" 15 && send "n" || true
check wait_for "$MENU_PROMPT" 30

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

echo ""
echo "--- Suite 3: Client Certificate Creation ---"

it "option 4 creates client certificate"
select_option "4"
wait_for "Enter client name:" 10 && send "$TEST_CLIENT" || true
wait_for "Generate .ovpn.*\(y/n\)" 30 && send "y" || true
check wait_for "$MENU_PROMPT" 60

it "client certificate file created"
check assert_file_exists "$OVPN_PKI/issued/$TEST_CLIENT.crt"

it "client certificate is valid X.509"
check assert_valid_cert "$OVPN_PKI/issued/$TEST_CLIENT.crt"

it "client private key created"
check assert_file_exists "$OVPN_PKI/private/$TEST_CLIENT.key"

it "client private key has 600 permissions"
check assert_file_perms "$OVPN_PKI/private/$TEST_CLIENT.key" "600"

it ".ovpn profile created"
check assert_file_exists "/etc/openvpn/$TEST_CLIENT.ovpn"

it ".ovpn profile contains inline CA block"
check assert_file_contains "/etc/openvpn/$TEST_CLIENT.ovpn" "<ca>"

it ".ovpn profile contains inline tls-crypt-v2 block"
check assert_file_contains "/etc/openvpn/$TEST_CLIENT.ovpn" "<tls-crypt-v2>"

# ── Suite 4: CRL — Revoke + Auto-renewal (option 6, r) ───────────────────────

echo ""
echo "--- Suite 4: CRL Revocation and Auto-renewal ---"

it "option 6 revokes client"
select_option "6"
wait_for "Enter client name to revoke:" 10 && send "$TEST_CLIENT" || true
wait_for "Confirm revocation.*\(yes/no\)" 15 && send "yes" || true
wait_for "Restart OpenVPN.*\(y/n\)" 15 && send "n" || true
check wait_for "$MENU_PROMPT" 30

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
wait_for "Select option:" 10 && send "1" || true
wait_for "days\|expires\|CRL" 15
press_enter

it "CRL install cron job (r → 4)"
select_option "r"
wait_for "Select option:" 10 && send "4" || true
press_enter

it "cron job installed in /etc/crontabs/root"
check assert_file_contains "/etc/crontabs/root" "openvpn-crl-renewal"

it "CRL cron status shows installed (r → 3)"
select_option "r"
wait_for "Select option:" 10 && send "3" || true
wait_for "installed\|enabled\|scheduled" 10
press_enter

# ── Done ──────────────────────────────────────────────────────────────────────

quit_script
kill_session

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""

[ "$FAIL" -eq 0 ]
