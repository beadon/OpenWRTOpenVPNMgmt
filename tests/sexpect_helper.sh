#!/bin/sh
# sexpect test helper — utilities for driving the interactive menu via sexpect.
# This file runs LOCALLY on the OpenWrt device alongside the script under test.
# The Mac-side runner (run_tests.sh) copies these files and invokes them via SSH.

SCRIPT_PATH="${SCRIPT_PATH:-/root/openvpn_server_management.sh}"
SEXPECT_SOCK="${SEXPECT_SOCK:-/tmp/sexpect-ovpn-$$.sock}"
MENU_PROMPT="Select an option:"
CONTINUE_PROMPT="Press Enter to continue"
TIMEOUT="${SEXPECT_TIMEOUT:-30}"

# ── Session lifecycle ─────────────────────────────────────────────────────────

spawn_script() {
    sexpect -sock "$SEXPECT_SOCK" spawn "$SCRIPT_PATH"
    wait_for "$MENU_PROMPT"
}

kill_session() {
    sexpect -sock "$SEXPECT_SOCK" kill 2>/dev/null || true
    rm -f "$SEXPECT_SOCK"
}

# ── Interaction primitives ────────────────────────────────────────────────────

wait_for() {
    local pattern="$1"
    local timeout="${2:-$TIMEOUT}"
    sexpect -sock "$SEXPECT_SOCK" expect -re "$pattern" -timeout "$timeout"
}

send() {
    sexpect -sock "$SEXPECT_SOCK" send -enter "$1"
}

# Wait for pattern then send reply — fails hard if pattern not seen in time.
# Use this for every known prompt so timeouts surface immediately.
expect_send() {
    local pattern="$1"
    local reply="$2"
    local timeout="${3:-$TIMEOUT}"
    wait_for "$pattern" "$timeout"
    send "$reply"
}

select_option() {
    send "$1"
}

# After an action that ends with "Press Enter to continue", consume it.
press_enter() {
    wait_for "$CONTINUE_PROMPT"
    send ""
    wait_for "$MENU_PROMPT"
}

# Wait for either the continue gate or menu prompt, handle whichever arrives.
# Returns once back at the menu.
after_action() {
    local timeout="${1:-15}"
    if sexpect -sock "$SEXPECT_SOCK" expect -re "$CONTINUE_PROMPT|$MENU_PROMPT" -timeout "$timeout"; then
        if sexpect -sock "$SEXPECT_SOCK" expect_out 2>/dev/null | grep -q "Press Enter"; then
            send ""
            wait_for "$MENU_PROMPT" "$timeout"
        fi
    fi
}

quit_script() {
    send "20"
    sexpect -sock "$SEXPECT_SOCK" wait 2>/dev/null || true
}

# ── Assertion helpers ─────────────────────────────────────────────────────────

assert_file_exists() {
    { test -f "$1" || test -d "$1"; } || { echo "FAIL: path missing: $1" >&2; return 1; }
}

assert_file_contains() {
    grep -q "$2" "$1" 2>/dev/null || { echo "FAIL: '$2' not in $1" >&2; return 1; }
}

assert_file_perms() {
    # BusyBox stat uses -c on some builds but not all; use ls -la instead
    local bits
    bits=$(ls -la "$1" 2>/dev/null | awk '{print $1}')
    case "$2" in
        600) [ "$bits" = "-rw-------" ] || { echo "FAIL: $1 perms: expected 600, got $bits" >&2; return 1; } ;;
        640) [ "$bits" = "-rw-r-----" ] || { echo "FAIL: $1 perms: expected 640, got $bits" >&2; return 1; } ;;
        400) [ "$bits" = "-r--------" ] || { echo "FAIL: $1 perms: expected 400, got $bits" >&2; return 1; } ;;
        *)   echo "FAIL: assert_file_perms: unsupported mode $2" >&2; return 1 ;;
    esac
}

assert_valid_cert() {
    openssl x509 -in "$1" -noout 2>/dev/null || { echo "FAIL: invalid cert: $1" >&2; return 1; }
}
