# Plan: Implementing Strict Mode and Error Handling

## Decision: Option C (Hybrid Approach)

**Agreed approach:**
- `set -u` globally for undefined variable protection
- `set -e` selectively in critical sections
- Trap-based cleanup for temp files
- Helper functions for consistent error reporting
- Incremental implementation for easy review
- Persistent logging deferred for later

**Testing:** Docker-based OpenWrt rootfs container

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
3. Consider adding `--dry-run` mode for testing

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

### Step 5: Wrap Critical Sections with `set -e`
Add `set -e` / `set +e` blocks around critical multi-step operations:
- EasyRSA initialization in `key_management_first_time()`
- Firewall configuration in `configure_vpn_firewall()`
- Server config generation in `generate_server_conf()`

**Files changed:** Critical functions only

---

### Future Enhancements (Deferred)
- Persistent logging to `/var/log/openvpn-mgmt.log`
- `--dry-run` mode for testing
- Input validation helpers with timeouts

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

### CRL Auto-Regeneration (Community Request)
From OpenWRT Forum (lantis1008):
- EasyRSA CRL expires after 180 days by default
- Add auto-detection and fix functionality
- Consider menu option for manual regeneration
