# Plan: Implementing Strict Mode and Error Handling
# Status: Phases 1-4 COMPLETE as of v2.7.0 (2026-04-29)

## Decision: Option C (Hybrid Approach) — Revised

**Agreed approach (updated after code audit):**
- `set -u` globally for undefined variable protection
- `run_cmd` guards on critical commands (replaces `set -e` blocks — see rationale below)
- Trap-based cleanup for temp files
- Helper functions for consistent error reporting
- Incremental implementation for easy review
- Persistent logging deferred for later

**Why `set -e` blocks were dropped from Phase 3:**
Code audit confirmed the script has ~70 intentional `2>/dev/null` suppressions on `uci get`,
`ip addr`, and similar commands that are *expected* to fail (existence checks, fallbacks).
`set -e` in busybox ash would trigger on these, breaking working functionality.
`key_management_first_time()` was already fully guarded by `run_cmd` in Phase 2 — nothing
remained for Phase 3 there. The correct approach for `configure_vpn_firewall()` and
`generate_server_conf()` is to add `run_cmd` guards to the remaining unguarded critical
steps (`uci commit` calls in production paths), consistent with Phase 2.

**Testing:** Docker-based OpenWrt rootfs container with ShellSpec framework

---

## Implementation Progress

### Phase 1: Foundation - COMPLETED
- [x] Add `set -u` at script start
- [x] Add temp file cleanup trap (`cleanup()`, `register_temp()`)
- [x] Add `error_exit()`, `warn()`, `info()` helper functions
- [x] Update temp file usage to use `register_temp()`

### Phase 2: Standardize Error Reporting - COMPLETED
- [x] Create `run_cmd()` helper for commands that should report failures
- [x] Update `create_client()` with error checking
- [x] Update `revoke_client()` with error checking
- [x] Update `renew_certificate()` with error checking
- [x] Update `key_management_first_time()` with error checking
- [x] Update `generate_server_conf()` file operations with error checking
- [x] Update `restore_server_conf()` with error checking
- [x] Update `generate_single_ovpn()` with error checking
- [ ] Add logging function for optional persistent logging (deferred)

### Phase 3: Critical Section Protection - REVISED

`set -e` blocks are **not appropriate** for this script (see Decision rationale above).
Phase 3 is now: guard unprotected `uci commit` calls in production paths.

- [x] `key_management_first_time()` — already fully protected by `run_cmd` in Phase 2, nothing to do
- [x] `configure_vpn_firewall()` — add `run_cmd` guard to `uci commit firewall` at line 987 (main success path)
- [x] `generate_server_conf()` — add `run_cmd` guard to `uci commit openvpn` at line 1576
- [x] `control_openvpn_server()` — add guards to `uci commit openvpn` at lines 3296 and 3308 (enable/disable paths)

**Also identified during audit (add to Phase 3):**
- [x] `generate_server_conf()` — verify `cat << EOF >` write succeeded at line 1457 (check file is non-empty after write)
- [x] Line 3661 `return 0 2>/dev/null || exit 0` — retained; correct POSIX idiom for ShellSpec test guard (return if sourced, exit if run directly)

### Phase 4: Enhanced Robustness - COMPLETED
- [x] Add input validation helpers: `validate_client_name()`, `validate_non_empty()`, `validate_non_negative_int()`
- [x] Wire `validate_client_name` into `create_client()` and `revoke_client()` (replaces inline empty checks)
- [x] Wire `validate_non_negative_int` into bandwidth limit input
- [x] Add `read -t 30` timeouts to destructive confirms: revoke certificate, stop server, disable boot
- ~~`--dry-run` mode~~ — dropped; script targets live OpenWrt systems, users are expected to make live edits

**Note:** Audit confirmed all other patterns are clean:
- All 57 `read` variables are properly declared before use — no initialization gaps
- All 3 temp files use `register_temp()` — no leaks
- All package operations use `pkg_*` helpers — no direct `opkg`/`apk` calls
- All `2>/dev/null` suppressions are appropriate (existence checks / fallbacks)

---

## Testing Framework

### ShellSpec (Unit Tests)
- BDD-style testing framework for POSIX shells
- Explicitly supports busybox ash (OpenWRT's shell)
- Tested on OpenWRT via Docker in ShellSpec's own CI
- Works with GitHub Actions
- Uses only POSIX-compliant commands

### sexpect Integration Tests — COMPLETED (v2.7.0+)

The authoritative integration test harness drives the full interactive menu on a real
OpenWrt device via `sexpect` (client/server PTY tool). 100 tests in ~12s on Pi 3.

**Files:**
```
tests/
├── run_tests.sh          # Mac-side launcher (SCP + SSH, pre-clean, tee to last_run.txt)
├── integration_test.sh   # Runs ON device — 14 suites, 100 tests
├── sexpect_helper.sh     # Primitives: spawn_script, expect_send, wait_for, assertions
└── last_run.txt          # Output of last run (gitignored)
```

**Suites:**
- Suite 0: Package installation cold-start (packages uninstalled by pre-clean)
- Suite 1: PKI init — EC/prime256v1, CA, server cert, TLS-crypt-v2
- Suite 2: server.conf generation — TLS 1.2, AES-256-GCM, dh none
- Suite 3: Client cert creation, .ovpn profile generation
- Suite 4: CRL revocation, crl-verify auto-enable, cron install
- Suite 5: Certificate inspection + bulk .ovpn (options 13, 15, 17, 18, 19)
- Suite 6: Complete CRL coverage (r→2 renew, r→5 remove cron)
- Suite 7: File permission check and fix (option 22)
- Suite 8: Firewall check and configure (options 10, 11)
- Suite 9: Server start/stop/restart (option s)
- Suite 10: Crypto config menu (option 2)
- Suite 11: Instance management (options i, l)
- Suite 12: Auto-detect server settings (option 4)
- Suite 13: Config mutations — restore, IPv6 toggle, performance (options 7, 8, 9)

**Verified on:** OpenWrt 25.12.2 / Pi 3, openvpn-mbedtls 2.7.1, easyrsa 3.2.1, sexpect 2.3.14

**Key design decisions:**
- `expect_send` replaces `wait_for && send` — hard-fails on timeout, prevents silent cascade
- `select_option` only sends — does not re-wait for menu prompt already consumed
- `require_suite` gates abort downstream suites on prerequisite failure
- All filesystem paths declared as variables — no hardcoded paths in test logic
- `apk list --installed` uses `grep "^<name>-"` (apk format: `<name>-<version>`)
- Pre-clean removes all of `/etc/easy-rsa` for cold-start PKI timing accuracy
- `openvpn` (not `openvpn-openssl`) used as apk install target — resolves to installed variant

### GitHub Actions CI Workflow — COMPLETED
See `.github/workflows/test.yml`. Three jobs: `shellcheck` → `unit-tests` → `integration-tests`.

**Supply chain decisions:**
- `actions/checkout` pinned by commit SHA (not floating tag)
- ShellSpec 0.28.1 installed from pinned GitHub release tarball with SHA256 verification
  — checksum stored in `.github/workflows/shellspec.sha256`
  — no pipe-to-shell, no URL shorteners
- OpenWrt Docker image built from local `./docker/Dockerfile` (no runtime pull of unverified image)
- shellcheck installed via `apt-get` (Debian package, version floats but low risk)

**To update ShellSpec:** download new tarball, run `sha256sum`, update both `test.yml` and `shellspec.sha256`.

### Running Tests Locally
```bash
# Real device integration tests (authoritative)
OPENWRT_HOST=<device-ip> ./tests/run_tests.sh

# ShellSpec unit tests (no Docker needed)
SHELLSPEC_VERSION="0.28.1"
SHELLSPEC_SHA256="350d3de04ba61505c54eda31a3c2ee912700f1758b1a80a284bc08fd8b6c5992"
curl -fsSL -o /tmp/shellspec-dist.tar.gz \
  "https://github.com/shellspec/shellspec/releases/download/${SHELLSPEC_VERSION}/shellspec-dist.tar.gz"
echo "${SHELLSPEC_SHA256}  /tmp/shellspec-dist.tar.gz" | sha256sum --check --strict
tar -xzf /tmp/shellspec-dist.tar.gz -C /tmp
sudo install -m 755 /tmp/shellspec/shellspec /usr/local/bin/shellspec
shellspec spec/unit/

# ShellSpec integration tests (requires Docker)
docker build --build-arg SSH_PUBLIC_KEY="$(cat ~/.ssh/id_rsa.pub)" -t openwrt-ovpn-test ./docker
shellspec spec/integration/
```

---

## Testing Environment

### Docker Container Setup

A clean OpenWrt rootfs container is used for testing. The script's dependencies (openvpn-openssl, openvpn-easy-rsa) are NOT pre-installed - this allows testing the script's installation flow.

**Location:** `docker/Dockerfile`

**Build:**
```bash
docker build --build-arg SSH_PUBLIC_KEY="$(cat ~/.ssh/id_rsa.pub)" -t openwrt-ovpn-test ./docker
```

**Run (interactive shell keeps container alive):**
```bash
docker run -it --name openwrt-test -p 2222:22 openwrt-ovpn-test
```

**Connect (from separate terminal):**
```bash
ssh root@localhost -p 2222
```

**Stop:**
Exit the interactive shell (Ctrl+D or `exit`) to cleanly stop the container.

**Credentials:**
- Root password: `admin`
- SSH key: Your local `~/.ssh/id_rsa.pub` (injected at build time)

### Development Workflow

1. Edit code locally in VS Code
2. Copy script to container: `scp -P 2222 openvpn_server_management.sh root@localhost:/root/`
3. Test in container via SSH
4. Iterate

---

## Current State Analysis

**Existing patterns found:**
- 71 uses of `return 0/1` for function exit codes
- 71 uses of `2>/dev/null` to suppress errors
- 54 file existence checks (`if [ -f ... ]`)
- 128 command substitutions (`var=$(command)`)
- 5 uses of `$?` to check exit status
- Only 7 uses of `|| return` or `|| echo` patterns

**Key challenges for strict mode:**
1. Many `2>/dev/null` patterns that legitimately suppress expected errors
2. Commands like `uci get` that are expected to fail (checking if config exists)
3. Interactive menu loop that should continue on function failures
4. Temporary files created without cleanup traps

---

## Option A: Full Strict Mode (`set -euo pipefail`)

**What it does:**
- `set -e` — Exit immediately if any command fails
- `set -u` — Exit if undefined variable is used
- `set -o pipefail` — Pipeline fails if any command in it fails

**Pros:**
- Maximum safety — catches bugs early
- Industry best practice for scripts
- Prevents silent failures from propagating

**Cons:**
- **High implementation effort** — requires auditing all 71+ `2>/dev/null` patterns
- Many intentional "failure checks" need `|| true` guards
- Commands like `uci get openvpn.server` that check existence will trigger exit
- Risk of breaking working functionality during transition

**Required changes:**
- Add `|| true` to ~50+ commands that legitimately can fail
- Change patterns like `uci get X 2>/dev/null` to `uci get X 2>/dev/null || true`
- Wrap the main menu loop to prevent function failures from exiting script
- Add explicit variable initialization for all optionally-set variables

---

## Option B: Partial Strict Mode (`set -u` only + explicit error handling)

**What it does:**
- `set -u` — Catch undefined variables (common bug source)
- Keep explicit `return 1` / `if` checks for command failures
- Add helper functions for common error patterns

**Pros:**
- Catches undefined variable bugs (real problem)
- Lower risk of breaking existing functionality
- Moderate implementation effort
- Maintains current explicit control flow

**Cons:**
- Doesn't catch silent command failures
- Still relies on manual error checking
- Less "strict" than full mode

**Required changes:**
- Initialize all variables that might be unset (e.g., in `read` commands)
- Add default values: `${var:-default}` patterns
- Create error handling helper functions

---

## Option C: Hybrid Approach (Recommended)

**What it does:**
- `set -u` globally for undefined variable protection
- `set -e` enabled selectively within critical functions only
- Add global error handler with `trap`
- Add temp file cleanup with `trap`
- Create standardized error reporting functions

**Implementation:**

```sh
#!/bin/sh
set -u  # Global: catch undefined variables

# Global error handler
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Cleanup handler for temp files
TEMP_FILES=""
cleanup() {
    for f in $TEMP_FILES; do
        rm -f "$f" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM

# Helper to register temp files
register_temp() {
    TEMP_FILES="$TEMP_FILES $1"
}

# Safe command execution with error message
run_cmd() {
    local desc="$1"
    shift
    if ! "$@"; then
        echo "ERROR: Failed to $desc" >&2
        return 1
    fi
}

# For critical sections that should fail fast:
critical_section() {
    set -e
    # ... critical commands ...
    set +e
}
```

**Pros:**
- Balanced safety vs. compatibility
- Undefined variables caught globally
- Critical operations can opt-in to strict mode
- Proper cleanup of temp files
- Standardized error reporting

**Cons:**
- More nuanced implementation
- Developers need to understand when to use `set -e` blocks

---

## Option D: Error Handling Functions Only (Minimal Change)

**What it does:**
- No `set -e` or `set -u`
- Add helper functions for consistent error handling
- Add temp file cleanup trap
- Standardize error message format

**Pros:**
- Lowest risk of breaking changes
- Easy to implement incrementally
- Improves consistency without changing behavior

**Cons:**
- Doesn't catch undefined variables
- Silent failures still possible
- Least improvement to actual error handling

---

## Comparison Matrix

| Aspect | Option A | Option B | Option C | Option D |
|--------|----------|----------|----------|----------|
| Safety | ★★★★★ | ★★★☆☆ | ★★★★☆ | ★★☆☆☆ |
| Implementation Effort | High | Medium | Medium | Low |
| Risk of Breaking | High | Low | Low | Very Low |
| Catches Undefined Vars | Yes | Yes | Yes | No |
| Catches Command Failures | Yes | Manual | Selective | Manual |
| Temp File Cleanup | Add | Add | Add | Add |

---

## Recommended Implementation: Option C (Hybrid)

### Phase 1: Foundation (Low Risk)
1. Add `set -u` at script start
2. Audit and fix undefined variable issues (initialize variables)
3. Add temp file cleanup trap
4. Add `error_exit()` and `warn()` helper functions

### Phase 2: Standardize Error Reporting
1. Create `run_cmd()` helper for commands that should report failures
2. Update critical functions to use standardized error reporting
3. Add logging function for optional persistent logging

### Phase 3: Critical Section Protection
1. Identify critical operations (cert generation, firewall changes, etc.)
2. Wrap critical sections with `set -e` / `set +e` blocks
3. Test thoroughly on OpenWrt device

### Phase 4: Enhanced Robustness
1. Add input validation helpers
2. Add timeout helpers for all `read` commands
3. ~~`--dry-run` mode~~ — dropped

---

## Specific Code Changes Preview

### Current problematic patterns to fix:

**1. Undefined variable risk:**
```sh
# Current (line 1890):
read -p "Enter client name: " NEW_CLIENT
# If user presses Ctrl+C, NEW_CLIENT is undefined

# Fixed:
NEW_CLIENT=""
read -p "Enter client name: " NEW_CLIENT || NEW_CLIENT=""
```

**2. Temp files without cleanup:**
```sh
# Current (line 2806):
temp_extract="/tmp/openvpn_client_check_$$"
# ... use file ...
rm -f "$temp_extract"  # Manual cleanup, missed on error

# Fixed:
temp_extract="/tmp/openvpn_client_check_$$"
register_temp "$temp_extract"
# ... use file ...
# Automatically cleaned up by trap
```

**3. Silent command failures:**
```sh
# Current (line 1898):
easyrsa build-client-full $NEW_CLIENT nopass
# No check if this succeeded!

# Fixed:
if ! easyrsa build-client-full "$NEW_CLIENT" nopass; then
    echo "ERROR: Failed to create client certificate"
    return 1
fi
```

---

## Implementation Steps (Incremental)

### Step 1: Add Error Handling Foundation
Add helper functions and trap near the top of the script (after configuration section):
- `error_exit()` - fatal error with message, exits script
- `warn()` - non-fatal warning message
- `cleanup()` - temp file cleanup function
- `register_temp()` - register temp files for cleanup
- `trap cleanup EXIT INT TERM` - automatic cleanup on exit

**Files changed:** Lines ~70-75 (after `update_instance_paths()`)

---

### Step 2: Enable `set -u` and Fix Undefined Variables
Add `set -u` at script start and fix all undefined variable issues:
- Initialize variables before `read` commands
- Add default values with `${var:-}` where needed
- Fix any variables used before assignment

**Files changed:** Line 1 area, plus scattered fixes

---

### Step 3: Add Temp File Cleanup
Update all temp file usage to use `register_temp()`:
- `check_active_connections()` - line 2806
- `check_fix_permissions()` - line 3221
- Any other temp file patterns

**Files changed:** Functions that create temp files

---

### Step 4: Add Critical Command Checks
Add error checking to critical operations that currently have none:
- `easyrsa` commands in `create_client()`, `revoke_client()`, `renew_certificate()`
- `openvpn --tls-crypt-v2` command in `create_client()`
- `opkg` commands in `ensure_at_installed()`, `install_luci_openvpn()`
- Key file operations in `generate_server_conf()`

**Files changed:** Certificate and setup functions

---

### Step 5: Guard Remaining `uci commit` Calls (replaces set -e plan)
Add `run_cmd` guards to unprotected `uci commit` calls in production paths:
- `configure_vpn_firewall()` line 987: `uci commit firewall`
- `generate_server_conf()` line 1576: `uci commit openvpn`
- `control_openvpn_server()` lines 3296, 3308: enable/disable paths
- `generate_server_conf()` line 1457: verify `cat << EOF >` write produced non-empty file
- Retain `return 0 2>/dev/null || exit 0` at line 3661 (correct POSIX ShellSpec test guard)

**Files changed:** `openvpn_server_management.sh` only

---

### Future Enhancements (Deferred)
- Input validation helpers with timeouts — COMPLETED in Phase 4
- ShellSpec test suite implementation (see Testing Framework section above)

### PID File — COMPLETED
- [x] `OVPN_MGMT_PID="/var/run/openvpn_mgmt.pid"` added to path constants
- [x] Written at startup (after test guard, before `reset`); duplicate-session guard exits with error if a live PID is found
- [x] Removed in `cleanup()` alongside temp files
- [x] Used by SSH disconnect regression test to confirm script is at the menu before dropping connection

### SSH Disconnect Regression Test — COMPLETED
- [x] Uses `sexpect spawn` on device — provides a real PTY regardless of whether run_tests.sh has a local tty
- [x] Waits for menu via `sexpect expect`, captures script PID via `sexpect get -pid` and daemon PID via `pgrep`
- [x] Kills sexpect daemon → closes PTY master → kernel delivers SIGHUP to script's foreground process group
- [x] Polls `kill -0 $SCRIPT_PID` for up to 5s to confirm exit
- Note: `ssh -tt` approach abandoned — fails silently when caller has no tty (Bash tool / CI context)

### Syslog Integration — COMPLETED (v2.9.0)
- [x] `log_action` helper: `logger -t "openvpn-mgmt" "$*"` — writes to system log (user.notice)
- [x] Filterable via `logread -e openvpn-mgmt`; no file I/O, no flash wear
- [x] 15 call sites: PKI init, server.conf generate/restore, firewall configure, server start/stop/restart/scheduled-restart, client create/revoke/renew, IPv6 enable/disable, instance create/switch
- Note: `/etc/openvpn/mgmt.log` file approach abandoned — syslog is OpenWrt best practice

---

## Project Standards & Conventions (Future Improvements)

### Commit Message Standards
**Current:** Informal lowercase messages without type prefixes
**Recommended:** Adopt [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

Format:
```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat:` - New feature (bumps MINOR version)
- `fix:` - Bug fix (bumps PATCH version)
- `docs:` - Documentation only
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `test:` - Adding or correcting tests
- `chore:` - Maintenance tasks

Examples:
```
feat(ipv6): add DHCPv6 mode for advanced IPv6 configuration
fix(permissions): resolve delimiter problem in permission checks
docs: update README with v2.5.0 features
refactor(menu): consolidate server control functions
```

Benefits:
- Automatic CHANGELOG generation
- Automatic SemVer bump determination
- Machine-readable commit history
- Clearer intent communication

### Variable Naming Conventions
**Current state:**
- Global config variables: `OVPN_*` prefix (UPPERCASE)
- Script metadata: `SCRIPT_*` prefix
- Local function variables: lowercase with `local` keyword
- True constants: `readonly` (SCRIPT_VERSION, OVPN_INSTANCE_TYPE)

**Guidelines:**
1. All global constants should use `readonly`
2. User-editable config variables should NOT be readonly
3. Dynamic variables (updated at runtime) should NOT be readonly
4. Use `${var:-default}` pattern for optional variables

### Function Naming
**Current:** `snake_case` with `verb_noun` pattern (good)

**Minor improvements to consider:**
| Current | Suggested | Reason |
|---------|-----------|--------|
| `check_fix_permissions` | `check_and_fix_permissions` | Clearer dual action |
| `key_management_first_time` | `initialize_pki` | More descriptive |
| `generate_single_ovpn` | `generate_client_ovpn` | Clearer target |

### Documentation Standards
**Recommended additions:**
1. **CHANGELOG.md** - Track version history with SemVer sections
2. **CONTRIBUTING.md** - Document commit message requirements
3. **Version badge** - Add to README header

### POSIX Compliance
Per [OpenWRT Code Style Guide](https://openwrt.org/code_style_guide):
- Use `#!/bin/sh` (Almquist shell, not bash)
- Validate with `shellcheck` for POSIX conformance
- Avoid bash-specific features

### CRL Auto-Regeneration (Community Request) — COMPLETED in v2.7.0
- check_crl_expiry(), enable_crl_verify(), renew_crl(), schedule_crl_renewal()
- Daily cron at 03:00, startup alert banner, r) menu option

---

## Feature Plan: Cryptography Hardening

### Background
The script currently sets no explicit crypto parameters, falling back to EasyRSA and
OpenVPN defaults: RSA 2048-bit keys, 2048-bit DH parameters, no TLS minimum version,
no explicit data cipher. These defaults are functional but dated for new deployments.

EasyRSA 3.x (shipped with `openvpn-easy-rsa` on OpenWrt) supports EC keys natively via
`EASYRSA_ALGO=ec` — same commands, no tooling change. EC eliminates the `gen-dh` step
entirely (ECDH is intrinsic to the curve), which meaningfully speeds up PKI init on
CPU-limited router hardware.

### Decisions
- **EC is the default** — `prime256v1` curve (NIST P-256); strong, fast, widely supported
  in OpenVPN 2.4+ clients
- **RSA is the compatibility option** — user-selectable 2048-bit (minimum, broad compat)
  or 4096-bit (maximum, slower on constrained hardware); 2048 is the lowest permitted
- **TLS hardening** — add `tls-version-min 1.2` and explicit `data-ciphers AES-256-GCM`
  to generated `server.conf` regardless of key type

### Phase 1: Config Section and PKI Init — COMPLETED
- [x] Add `OVPN_CRYPTO_ALGO` to user config section (default: `ec`)
- [x] Add `OVPN_CRYPTO_CURVE` to user config section (default: `prime256v1`)
- [x] Add `OVPN_RSA_KEY_SIZE` to user config section (default: `2048`, options: `2048`, `4096`)
- [x] Update `key_management_first_time()`: EC path skips gen-dh; RSA path keeps it with size message

### Phase 2: server.conf Hardening — COMPLETED
- [x] Add `tls-version-min 1.2` to generated `server.conf`
- [x] Add `data-ciphers AES-256-GCM` to generated `server.conf`
- [x] EC path: `dh none` in server.conf
- [x] RSA path: `dh ${OVPN_PKI}/dh.pem`

### Phase 3: Menu Options — COMPLETED
- [x] Add `k) Configure cryptography settings (currently: <algo>)` under Setup & Integration
- [x] `configure_crypto()`: shows current settings, warns if PKI initialized, EC/RSA selection
- [x] `show_crypto_summary()`: reusable summary printed at PKI init and configure_crypto
- [x] PKI init prints algo summary on completion

### Phase 4: Documentation — COMPLETED
- [x] Update README: explain EC vs RSA choice, compatibility note for pre-2.4 clients
- [x] Update README: note that `gen-dh` is skipped for EC (faster init)
- [x] Bump version to v2.8.0 on completion

### Compatibility Note
RSA 2048-bit is the minimum permitted — no option for smaller sizes.
Pre-OpenVPN 2.4 clients (~2017 and earlier) do not support EC certificates.
For self-managed deployments with modern clients, EC is always the right choice.

### IPv6 ULA Range + Config Persistence — PENDING

#### Problem
The hardcoded default `OVPN_IPV6_POOL="fd42:4242:4242:1194::/64"` violates RFC 4193:
the 40-bit global ID must be pseudo-randomly generated per-site to avoid collisions
between networks. The current value is a recognisable placeholder, not a random prefix.

Additionally, IPv6 settings (pool, mode, max clients) are only held in memory — they
reset to script defaults on every run, so any customisation made via option 8 is lost.

#### Design Decision
Use `server.conf` as the source of truth wherever possible:
- **Real OpenVPN directives** are the primary store: `server-ipv6`, `push "route-ipv6"`,
  `push "dhcp-option DNS6"` — option 4 (auto-detect) already reads these back.
- **Structured comments** (`# openvpn-mgmt: key=value`) only for the two values that
  have no OpenVPN directive equivalent: `ipv6_mode` and `ipv6_max_clients`.
  OpenVPN ignores these lines; the script greps them on startup.
- No separate config file — `server.conf` is self-contained and human-readable.

#### IPv6 mode inference rule
If `server-ipv6` is present and no DHCPv6 directives are present → infer `static`.
The `# openvpn-mgmt: ipv6_mode=dhcpv6` comment is only needed if mode is `dhcpv6`.
For static mode the comment is optional (inferred), but written for explicitness.

#### Implementation Plan

**Phase 1 — RFC 4193-compliant prefix generation**
- [ ] Add `generate_ula_prefix()` helper: reads 5 random bytes from `/dev/urandom`,
      formats as `fdXX:XXXX:XXXX::/48` (standard site prefix length per RFC 4193 §3.2)
- [ ] Call at server.conf generation time (option 5) when IPv6 is enabled and
      `OVPN_IPV6_POOL` is still the factory default — never overwrite a user-customised value
- [ ] Remove hardcoded `fd42:4242:4242:1194::/64` default; replace with empty string
      sentinel that triggers generation on first use
- [ ] Subnet for VPN pool: take the generated `/48` and assign `::1194::/64` as the
      tunnel subnet (the VPN port number as the subnet ID — memorable, deterministic)

**Phase 2 — Read IPv6 config back from server.conf at startup**
- [ ] Add `load_ipv6_config_from_conf()`: called after `server.conf` is confirmed to exist;
      parses `server-ipv6`, `# openvpn-mgmt: ipv6_mode`, `# openvpn-mgmt: ipv6_max_clients`
      and populates `OVPN_IPV6_POOL`, `OVPN_IPV6_MODE`, `OVPN_IPV6_POOL_SIZE`
- [ ] Write `# openvpn-mgmt:` hints into server.conf at generation time (option 5)
      and update them when option 8 (toggle IPv6) makes changes
- [ ] Option 4 (auto-detect) already reads `server-ipv6` — ensure it sets
      `OVPN_IPV6_POOL` consistently so the two paths agree

**Phase 3 — ULA conflict detection**
- [ ] Extend existing `check_ipv6_subnet_conflict()` to also check the generated prefix
      against the router's LAN IPv6 prefix (via `network_get_ipaddr6` or `ip -6 addr`)
- [ ] Regenerate and retry (up to 3 times) if a collision is detected — extremely unlikely
      with a random /48 but correct behaviour

**Phase 4 — Documentation + tests**
- [ ] Update README IPv6 section: explain RFC 4193, show example generated prefix,
      document the `# openvpn-mgmt:` comment format
- [ ] Update Address Pool diagram to show the /48 → /64 subnet assignment
- [ ] Add integration test assertions: generated prefix starts with `fd`, is not the
      old placeholder, and appears correctly in server.conf

#### Key constraints
- `/dev/urandom` is always available on OpenWrt (in-kernel CSPRNG, no package needed)
- `printf` / `awk` for hex formatting — no `bc` or Python
- Must not overwrite a prefix the user explicitly set via option 8
- `# openvpn-mgmt:` comments must survive a restore-from-backup (option 7) unchanged

### Docker Test Environment (Future)
Current limitation: Using `openwrt/rootfs:x86-64-23.05.5` for testing.

Issues with newer versions:
- `x86-64-openwrt-24.10` and `x86-64-24.10-SNAPSHOT` have broken kmods URLs
- `x86_64` tag is minimal image without opkg
- SNAPSHOT versions have unstable package repository URLs

Future options to consider:
- Monitor for stable 24.10.x release tags
- Build custom OpenWRT Docker image from ImageBuilder
- Use OpenWRT SDK container for more control
- Alternative: test on actual hardware or full VM instead of Docker
