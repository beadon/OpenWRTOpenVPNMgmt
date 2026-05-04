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
OVPN_MGMT_PID="/var/run/openvpn_mgmt.pid"

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

# ── SSH disconnect regression test ───────────────────────────────────────────
# Verify that the script exits when the SSH client drops (kernel-delivered
# SIGHUP via PTY close), rather than spinning at 100% CPU on a deleted PTY.
#
# Mechanism: sexpect spawns the script on the device with a real PTY (works
# regardless of whether run_tests.sh has a local tty). Once the script reaches
# the menu, we kill the sexpect daemon — this closes the PTY master and
# delivers SIGHUP to the script's foreground process group, exactly as the
# kernel does on a real SSH disconnect.
echo ""
echo "--- SSH disconnect regression test ---"

# Clean up any leftover state from the integration suite
ssh "root@${OPENWRT_HOST}" \
    "pkill -f openvpn_server_management.sh 2>/dev/null; pkill -f 'sexpect.*huptest' 2>/dev/null; rm -f /tmp/sexpect-huptest.sock ${OVPN_MGMT_PID}; true" \
    2>/dev/null || true

# Spawn the script via sexpect on the device (provides a real PTY).
# Wait for the menu prompt, then return the sexpect daemon PID and script PID.
PIDS=$(ssh "root@${OPENWRT_HOST}" '
    SOCK=/tmp/sexpect-huptest.sock
    sexpect -sock "$SOCK" spawn /root/openvpn_server_management.sh
    sexpect -sock "$SOCK" expect -re "Select an option:" -timeout 30 >/dev/null 2>&1 || exit 1
    SCRIPT_PID=$(sexpect -sock "$SOCK" get -pid 2>/dev/null)
    DAEMON_PID=$(pgrep -f "sexpect -sock $SOCK" 2>/dev/null | head -1)
    printf "%s %s\n" "$SCRIPT_PID" "$DAEMON_PID"
' 2>/dev/null) || true

REMOTE_PID=$(printf '%s' "$PIDS" | awk '{print $1}' | tr -d '[:space:]')
SEXP_PID=$(printf  '%s' "$PIDS" | awk '{print $2}' | tr -d '[:space:]')

if [ -z "$REMOTE_PID" ] || [ -z "$SEXP_PID" ]; then
    ssh "root@${OPENWRT_HOST}" "pkill -f 'sexpect.*huptest' 2>/dev/null; true" 2>/dev/null || true
    echo "FAIL: script did not reach menu within 30s (script_pid='${REMOTE_PID}' sexp_pid='${SEXP_PID}')"
    exit 1
fi

echo "  script PID: $REMOTE_PID  sexpect daemon PID: $SEXP_PID"

# Simulate SSH disconnect: kill the sexpect daemon to close the PTY master.
# The kernel delivers SIGHUP to the script's foreground process group.
ssh "root@${OPENWRT_HOST}" "kill ${SEXP_PID}" 2>/dev/null || true

# Wait up to 5 seconds for the remote script to exit.
ELAPSED=0
while ssh "root@${OPENWRT_HOST}" "kill -0 ${REMOTE_PID}" 2>/dev/null; do
    if [ $ELAPSED -ge 5 ]; then
        ssh "root@${OPENWRT_HOST}" "kill -9 ${REMOTE_PID}" 2>/dev/null || true
        echo "FAIL: script (pid ${REMOTE_PID}) still running ${ELAPSED}s after PTY close — HUP exit not working"
        exit 1
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

echo "PASS: script exited within ${ELAPSED}s of PTY close (pid ${REMOTE_PID})"
echo ""
