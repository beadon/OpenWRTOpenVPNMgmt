#!/bin/sh
# Mac-side launcher — copies test files to the OpenWrt device and runs the
# integration suite in a single SSH session. All sexpect operations happen
# locally on the device; no nested SSH loops.
#
# Usage:
#   OPENWRT_HOST=192.168.88.32 ./tests/run_tests.sh

set -e

OPENWRT_HOST="${OPENWRT_HOST:?Set OPENWRT_HOST to the device IP}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Path constants — must match integration_test.sh and openvpn_server_management.sh
OVPN_EASYRSA="/etc/easy-rsa"
OVPN_CONF="/etc/openvpn/server.conf"
OVPN_DIR="/root/ovpn_config_out"
CRONTAB="/etc/crontabs/root"

echo "Copying files to $OPENWRT_HOST..."
scp "$REPO_ROOT/openvpn_server_management.sh" \
    "$SCRIPT_DIR/sexpect_helper.sh" \
    "$SCRIPT_DIR/integration_test.sh" \
    "root@${OPENWRT_HOST}:/root/"

ssh "root@${OPENWRT_HOST}" 'chmod +x /root/integration_test.sh /root/sexpect_helper.sh /root/openvpn_server_management.sh'

echo "Pre-cleaning device state..."
# shellcheck disable=SC2087
ssh "root@${OPENWRT_HOST}" "sh -s" <<CLEAN
set -e
killall sexpect 2>/dev/null || true
killall openvpn_server_management.sh 2>/dev/null || true
kill $(pgrep -f "openvpn_server_management") 2>/dev/null || true
/etc/init.d/openvpn stop 2>/dev/null || true
rm -f /tmp/sexpect*.sock "$OVPN_CONF" "$CRONTAB"
rm -rf "$OVPN_EASYRSA" "$OVPN_DIR"
mkdir -p "$OVPN_EASYRSA" "$(dirname "$OVPN_CONF")"
# Uninstall packages so Suite 0 exercises a real install
if command -v apk >/dev/null 2>&1; then
    apk del openvpn-easy-rsa at 2>/dev/null || true
else
    opkg remove openvpn-easy-rsa at 2>/dev/null || true
fi
echo "clean"
CLEAN

LOG="$SCRIPT_DIR/last_run.txt"
echo "Running integration tests on $OPENWRT_HOST..."
echo ""
ssh "root@${OPENWRT_HOST}" \
    'SCRIPT_PATH=/root/openvpn_server_management.sh /root/integration_test.sh' \
    | tee "$LOG"
echo ""
echo "Full output saved to: $LOG"
