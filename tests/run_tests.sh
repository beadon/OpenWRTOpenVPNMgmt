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

echo "Copying files to $OPENWRT_HOST..."
scp "$REPO_ROOT/openvpn_server_management.sh" \
    "$SCRIPT_DIR/sexpect_helper.sh" \
    "$SCRIPT_DIR/integration_test.sh" \
    "root@${OPENWRT_HOST}:/root/"

ssh "root@${OPENWRT_HOST}" 'chmod +x /root/integration_test.sh /root/sexpect_helper.sh /root/openvpn_server_management.sh'

echo "Pre-cleaning device state..."
ssh "root@${OPENWRT_HOST}" \
    'killall sexpect 2>/dev/null; rm -f /tmp/sexpect*.sock /etc/openvpn/server.conf /etc/crontabs/root; rm -rf /etc/easy-rsa/pki /root/ovpn_config_out; mkdir -p /etc/easy-rsa /etc/openvpn; echo "clean"'

LOG="$SCRIPT_DIR/last_run.txt"
echo "Running integration tests on $OPENWRT_HOST..."
echo ""
ssh "root@${OPENWRT_HOST}" \
    'SCRIPT_PATH=/root/openvpn_server_management.sh /root/integration_test.sh' \
    | tee "$LOG"
echo ""
echo "Full output saved to: $LOG"
