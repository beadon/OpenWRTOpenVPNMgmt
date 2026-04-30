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

select_option() {
    wait_for "$MENU_PROMPT"
    send "$1"
}

# Consume a "Press Enter to continue" gate then wait for menu to redraw.
press_enter() {
    wait_for "$CONTINUE_PROMPT"
    send ""
    wait_for "$MENU_PROMPT"
}

# After sending a menu option, wait for either the "Press Enter" gate or
# the menu prompt — whichever comes first. Sends enter if gated, then
# waits for the menu. No fixed sleep; returns as soon as output arrives.
after_action() {
    local timeout="${1:-15}"
    if sexpect -sock "$SEXPECT_SOCK" expect -re "$CONTINUE_PROMPT|$MENU_PROMPT" -timeout "$timeout"; then
        # Matched — check which one via lookback
        if sexpect -sock "$SEXPECT_SOCK" expect_out 2>/dev/null | grep -q "Press Enter"; then
            send ""
            wait_for "$MENU_PROMPT" "$timeout"
        fi
        # else: already at menu prompt, nothing to do
    fi
}

quit_script() {
    wait_for "$MENU_PROMPT"
    send "20"
    sexpect -sock "$SEXPECT_SOCK" wait 2>/dev/null || true
}

# ── Assertion helpers ─────────────────────────────────────────────────────────

assert_file_exists() {
    test -f "$1" || { echo "FAIL: file missing: $1" >&2; return 1; }
}

assert_file_contains() {
    grep -q "$2" "$1" 2>/dev/null || { echo "FAIL: '$2' not in $1" >&2; return 1; }
}

assert_file_perms() {
    local actual
    actual=$(stat -c '%a' "$1" 2>/dev/null)
    [ "$actual" = "$2" ] || { echo "FAIL: $1 perms: expected $2, got $actual" >&2; return 1; }
}

assert_valid_cert() {
    openssl x509 -in "$1" -noout 2>/dev/null || { echo "FAIL: invalid cert: $1" >&2; return 1; }
}
