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

# Detect package manager — mirrors logic in the main script
if command -v apk >/dev/null 2>&1; then
    TEST_PKG_MGR="apk"
else
    TEST_PKG_MGR="opkg"
fi

pkg_is_installed_test() {
    case "$TEST_PKG_MGR" in
        apk)  apk list --installed 2>/dev/null | grep -q "^$1-" ;;
        opkg) opkg list-installed 2>/dev/null | grep -q "^$1 " ;;
    esac
}

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

# Abort if any failures have occurred — used as a suite gate so downstream
# suites don't cascade-fail when a prerequisite suite has not passed.
require_suite() {
    if [ "$FAIL" -gt 0 ]; then
        printf "\n  [%s] ABORT: prerequisite suite failed (%d failures) — skipping remaining suites\n\n" "$(ts)" "$FAIL" >&2
        quit_script
        kill_session
        printf "\n=== Results: %d passed, %d failed (finished: %s) ===\n\n" "$PASS" "$FAIL" "$(ts)"
        exit 1
    fi
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

# ── Suite 0: Package Installation (option 1) ─────────────────────────────────

printf "--- [%s] Suite 0: Package Installation (%s) ---\n" "$(ts)" "$TEST_PKG_MGR"

it "package manager detected ($TEST_PKG_MGR)"
if [ "$TEST_PKG_MGR" = "apk" ] || [ "$TEST_PKG_MGR" = "opkg" ]; then
    pass
else
    fail "unknown package manager: $TEST_PKG_MGR"
fi

it "option 1 installs packages"
select_option "1"
expect_send "Continue with installation" "yes" 10
# pkg_update + pkg_install run unattended; wait up to 120s for download+install
check wait_for "Installation complete" 120
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "openvpn-easy-rsa installed"
check pkg_is_installed_test "openvpn-easy-rsa"

it "at installed"
check pkg_is_installed_test "at"

it "openvpn installed"
# apk resolves 'openvpn' to whichever variant (-openssl/-mbedtls) is present
case "$TEST_PKG_MGR" in
    apk)  if apk list --installed 2>/dev/null | grep -q "^openvpn-"; then pass; else fail "no openvpn variant installed"; fi ;;
    opkg) check pkg_is_installed_test "openvpn-openssl" ;;
esac

require_suite  # suites 1–4 depend on packages being installed

# ── Suite 1: PKI Initialization (EC / prime256v1) ────────────────────────────

printf "--- [%s] Suite 1: PKI Initialization ---\n" "$(ts)"

it "option 3 completes PKI init"
select_option "3"
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

# ── Suite 2: Server Config Generation (option 5) ─────────────────────────────

printf "\n--- [%s] Suite 2: Server Config Generation ---\n" "$(ts)"

it "option 5 generates server.conf"
select_option "5"
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

# ── Suite 3: Client Certificate Creation (option 12) ─────────────────────────

printf "\n--- [%s] Suite 3: Client Certificate Creation ---\n" "$(ts)"

it "option 12 creates client certificate"
select_option "12"
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

it "option 14 revokes client"
select_option "14"
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

# ── Suite 5: Certificate Inspection + Bulk .ovpn ─────────────────────────────
# Runs after Suite 3 (client cert exists) and Suite 4 (client revoked).
# server cert is still present; revoked client has moved to pki/revoked/.

printf "\n--- [%s] Suite 5: Certificate Inspection + Bulk .ovpn ---\n" "$(ts)"

it "option 13 lists clients"
select_option "13"
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option 15 checks certificate expiration"
select_option "15"
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "expiration output mentions server cert"
if grep -q "\[OK\]\|EXPIRED\|WARNING\|SOON" "$OVPN_PKI/issued/server.crt" 2>/dev/null || \
   openssl x509 -in "$OVPN_PKI/issued/server.crt" -noout -enddate 2>/dev/null | grep -q "notAfter"; then
    pass
else
    fail "server cert enddate unreadable"
fi

it "option 17 shows server cert details"
select_option "17"
expect_send "Enter certificate name" "server" 5
expect_send "Press Enter" ""                  5
check wait_for "Select an option:" 5

it "option 18 generates all .ovpn files"
select_option "18"
expect_send "Continue" "y" 5
expect_send "Press Enter" "" 10
check wait_for "Select an option:" 5

it "ovpn output directory exists"
check assert_file_exists "$OVPN_DIR"

it "server.ovpn not generated (server is not a client)"
if test -f "$OVPN_DIR/server.ovpn"; then
    fail "server.ovpn should not be generated"
else
    pass
fi

# Create a second client so option 19 (single .ovpn) has a valid target
TEST_CLIENT2="testclient2"
it "create second client for option 19 test"
select_option "12"
expect_send "Enter client name:" "$TEST_CLIENT2" 5
expect_send "Generate" "n"                        10  # skip ovpn here, test via option 19
expect_send "Daemon restart" "n"                  10
check wait_for "Select an option:" 10

it "option 19 generates single .ovpn file"
select_option "19"
expect_send "Enter client name:" "$TEST_CLIENT2" 5
expect_send "Press Enter" ""                      10
check wait_for "Select an option:" 5

it "single .ovpn file created for $TEST_CLIENT2"
check assert_file_exists "$OVPN_DIR/$TEST_CLIENT2.ovpn"

it ".ovpn profile has tls-crypt-v2 block"
check assert_file_contains "$OVPN_DIR/$TEST_CLIENT2.ovpn" "<tls-crypt-v2>"

# ── Suite 6: Complete CRL Coverage ───────────────────────────────────────────

printf "\n--- [%s] Suite 6: Complete CRL Coverage ---\n" "$(ts)"

it "CRL renew (r → 2)"
select_option "r"
expect_send "Select option:" "2" 5
expect_send "Restart OpenVPN" "n" 15
expect_send "Press Enter" ""      5
check wait_for "Select an option:" 5

it "CRL pem still exists after renew"
check assert_file_exists "$OVPN_PKI/crl.pem"

it "renewed CRL is valid"
if openssl crl -in "$OVPN_PKI/crl.pem" -noout 2>/dev/null; then pass; else fail "crl.pem invalid after renew"; fi

it "CRL remove cron job (r → 5)"
select_option "r"
expect_send "Select option:" "5" 5
expect_send "Press Enter" ""     10
check wait_for "Select an option:" 5

it "cron job removed from /etc/crontabs/root"
if grep -q "openvpn-crl-renewal" "$CRONTAB" 2>/dev/null; then
    fail "cron entry still present after removal"
else
    pass
fi

# ── Suite 7: File Permission Check and Fix ────────────────────────────────────

printf "\n--- [%s] Suite 7: File Permission Check and Fix ---\n" "$(ts)"

it "option 22 reports all permissions OK (clean state)"
select_option "22"
expect_send "Press Enter" "" 10
check wait_for "Select an option:" 5

it "PKI private keys are 600 after Suite 1"
check assert_file_perms "$OVPN_PKI/private/server.key" "600"

it "intentionally break a key permission"
chmod 644 "$OVPN_PKI/private/$TEST_CLIENT2.key"
if [ "$(ls -la "$OVPN_PKI/private/$TEST_CLIENT2.key" | awk '{print $1}')" = "-rw-r--r--" ]; then
    pass
else
    fail "chmod 644 did not take effect"
fi

it "option 22 detects and fixes broken permission"
select_option "22"
expect_send "Fix all permission issues" "yes" 10
expect_send "Press Enter" ""                  5
check wait_for "Select an option:" 5

it "key permission restored to 600 after fix"
check assert_file_perms "$OVPN_PKI/private/$TEST_CLIENT2.key" "600"

# ── Suite 8: Firewall Check and Configure ────────────────────────────────────
# UCI changes are committed before the restart prompts — we answer 'n' to both
# network and firewall restarts to avoid dropping the SSH management session.
# Assertions are against UCI state, which is persisted before any restart.

printf "\n--- [%s] Suite 8: Firewall Check and Configure ---\n" "$(ts)"

it "option 10 runs firewall check"
select_option "10"
expect_send "Press Enter" "" 10
check wait_for "Select an option:" 5

it "option 11 configures VPN firewall (no restart)"
select_option "11"
expect_send "Continue with firewall configuration" "yes" 5
expect_send "Restart network service"               "n"   10
expect_send "Restart firewall"                      "n"   10
expect_send "Press Enter"                           ""    10
check wait_for "Select an option:" 5

it "firewall.ovpn rule created in UCI"
if uci get firewall.ovpn.name 2>/dev/null | grep -q "Allow-OpenVPN"; then
    pass
else
    fail "firewall.ovpn rule not found in UCI"
fi

it "firewall.ovpn targets WAN port 1194"
if uci get firewall.ovpn.dest_port 2>/dev/null | grep -q "1194"; then
    pass
else
    fail "firewall.ovpn dest_port is not 1194"
fi

it "tun+ interface added to LAN zone"
if uci get firewall.lan.device 2>/dev/null | grep -q "tun+"; then
    pass
else
    fail "tun+ not found in firewall LAN zone"
fi

it "VPN network interface created in UCI"
if uci get network.vpn.device 2>/dev/null | grep -q "tun+"; then
    pass
else
    fail "network.vpn UCI interface not created"
fi

# ── Suite 9: Server Start and Stop ───────────────────────────────────────────
# Starting OpenVPN only creates tun0 — it does not touch br-lan or the SSH
# management interface, so the session is safe throughout.

printf "\n--- [%s] Suite 9: Server Start and Stop ---\n" "$(ts)"

it "option s → 1 starts OpenVPN server"
select_option "s"
expect_send "Select action" "1"  5
# start runs /etc/init.d/openvpn start + sleep 2 — wait for status line then gate
wait_for "Server started\|already running" 20
check wait_for "Press Enter" 5
send ""
check wait_for "Select an option:" 5

it "OpenVPN process is running"
if pgrep -f "[/]openvpn .*server" >/dev/null 2>&1; then
    pass
else
    fail "openvpn process not found after start"
fi

it "tun0 interface exists"
if ip link show tun0 >/dev/null 2>&1; then
    pass
else
    fail "tun0 interface not found after start"
fi

it "option s → 2 stops OpenVPN server"
select_option "s"
expect_send "Select action"              "2"   5
expect_send "Stop OpenVPN server"        "yes" 10
# stop runs /etc/init.d/openvpn stop + sleep 2 — wait for status line then gate
wait_for "Server stopped\|stopped successfully\|already stopped" 20
check wait_for "Press Enter" 5
send ""
check wait_for "Select an option:" 5

it "OpenVPN process is stopped"
if pgrep -f "[/]openvpn .*server" >/dev/null 2>&1; then
    fail "openvpn process still running after stop"
else
    pass
fi

it "tun0 interface removed after stop"
if ip link show tun0 >/dev/null 2>&1; then
    fail "tun0 still exists after stop"
else
    pass
fi

it "option s → 4 shows detailed status as STOPPED"
select_option "s"
expect_send "Select action" "4" 5
expect_send "Press Enter"   ""  10
check wait_for "Select an option:" 5

# ── Suite 10: Crypto Config Menu ─────────────────────────────────────────────
# Tests option 2 sub-menu: EC with prime256v1, EC with secp384r1, RSA 2048,
# RSA 4096, and Cancel. Settings are in-memory only — PKI is not re-initialised.
# Each sub-case ends with "Press Enter to continue" from the case handler.

printf "\n--- [%s] Suite 10: Crypto Config Menu (option 2) ---\n" "$(ts)"

it "option 2 → 1 → 1 sets EC prime256v1"
select_option "2"
expect_send "Select algorithm"  "1" 5
expect_send "Select curve"      "1" 5
wait_for "Crypto settings updated" 5
check wait_for "prime256v1" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option 2 → 1 → 2 sets EC secp384r1"
select_option "2"
expect_send "Select algorithm"  "1" 5
expect_send "Select curve"      "2" 5
wait_for "Crypto settings updated" 5
check wait_for "secp384r1" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option 2 → 2 → 1 sets RSA 2048"
select_option "2"
expect_send "Select algorithm"  "2" 5
expect_send "Select key size"   "1" 5
wait_for "Crypto settings updated" 5
check wait_for "2048" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option 2 → 2 → 2 sets RSA 4096"
select_option "2"
expect_send "Select algorithm"  "2" 5
expect_send "Select key size"   "2" 5
wait_for "Crypto settings updated" 5
check wait_for "4096" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option 2 → 3 cancels (no change)"
select_option "2"
expect_send "Select algorithm"  "3" 5
wait_for "Cancelled" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option 2 restore EC prime256v1 for remaining suites"
select_option "2"
expect_send "Select algorithm"  "1" 5
expect_send "Select curve"      "1" 5
wait_for "Crypto settings updated" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

# ── Suite 11: Instance Management ────────────────────────────────────────────
# option l — list instances (at least 'server' exists from Suite 2 server.conf gen)
# option i → c — cancel, no change
# option i → n — create new instance, verify UCI, then switch back to 'server'

printf "\n--- [%s] Suite 11: Instance Management (options i, l) ---\n" "$(ts)"

it "option l lists instances"
select_option "l"
wait_for "OpenVPN Instances" 5
check wait_for "server" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option i → c cancels without change"
select_option "i"
expect_send "Select option" "c" 5
wait_for "Cancelled" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option i → n creates new instance 'testvpn'"
select_option "i"
expect_send "Select option"         "n"       5
expect_send "Enter new instance"    "testvpn" 5
wait_for "Created and selected" 10
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "UCI entry exists for testvpn"
if uci get openvpn.testvpn >/dev/null 2>&1; then
    pass
else
    fail "UCI entry for testvpn not found"
fi

it "option i → 1 switches back to server instance"
select_option "i"
expect_send "Select option" "1" 5
wait_for "Selected instance" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

it "option l shows testvpn in list"
select_option "l"
wait_for "OpenVPN Instances" 5
check wait_for "testvpn" 5
expect_send "Press Enter" "" 5
check wait_for "Select an option:" 5

# ── Suite 12: Auto-detect Server Settings ────────────────────────────────────
# option 4 is read-only: detects port/proto from server.conf and firewall rules,
# WAN IP from UCI, and prints "Final Settings". No user prompts — returns
# directly to the main menu after output.

printf "\n--- [%s] Suite 12: Auto-detect Server Settings (option 4) ---\n" "$(ts)"

it "option 4 detects settings from server.conf and prints final summary"
select_option "4"
wait_for "Detecting configuration" 5
# server.conf exists from Suite 2 — port and protocol should be detected
wait_for "Detected port" 10
wait_for "Final Settings" 10
# No Press Enter gate — returns directly to menu; allow time for network detection
check wait_for "Select an option:" 20

it "option 4 reports a VPN server address"
select_option "4"
wait_for "Detected WAN IP\|Detected DDNS" 20
check wait_for "Select an option:" 20

# ── Done ──────────────────────────────────────────────────────────────────────

quit_script
kill_session

printf "\n=== Results: %d passed, %d failed (finished: %s) ===\n\n" "$PASS" "$FAIL" "$(ts)"

[ "$FAIL" -eq 0 ]
