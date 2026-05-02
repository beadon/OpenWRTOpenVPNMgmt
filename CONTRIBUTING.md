# Contributing Guidelines

Thank you for your interest in contributing to the OpenWRT OpenVPN Management Script.

## Basic Guidelines

All contributions should follow these guidelines:

- Test changes on an actual OpenWRT device or the Docker test environment
- Ensure POSIX shell compliance (script runs on `ash`, not `bash`)
- Maintain backwards compatibility with OpenWRT v20.x and later
- Follow existing code style and naming conventions

## Code Style

### Shell Script Standards

- Use `#!/bin/sh` shebang (Almquist shell, not bash)
- Validate with `shellcheck` for POSIX conformance
- Avoid bash-specific features (arrays, `[[`, process substitution)
- Quote all variable expansions: `"$variable"` not `$variable`

### Variable Naming

- Global constants: `UPPERCASE_WITH_UNDERSCORES`
- Configuration variables: `OVPN_*` prefix
- Local function variables: `lowercase_with_underscores` using `local`
- True constants should use `readonly`

### Function Naming

- Use `snake_case` with `verb_noun` pattern
- Examples: `generate_server_conf`, `check_active_connections`

## Commit Message Standards

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

- `feat:` - New feature (bumps MINOR version)
- `fix:` - Bug fix (bumps PATCH version)
- `docs:` - Documentation changes only
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `test:` - Adding or correcting tests
- `chore:` - Maintenance tasks (versioning, CI, etc.)

### Examples

```
feat(ipv6): add DHCPv6 mode for advanced IPv6 configuration
fix(permissions): resolve delimiter problem in permission checks
docs(readme): add architecture diagrams
refactor(menu): consolidate server control functions
```

### Rules

- Subject line should be lowercase after the type prefix
- No period at the end of the subject line
- Keep subject line under 72 characters
- Use imperative mood ("add feature" not "added feature")
- No unicode or emoji characters in commit messages
- Keep commit messages concise; avoid redundant or verbose descriptions
- Use `Co-Authored-By:` footer for collaborative commits (do not duplicate attribution)

## Pull Request Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following the guidelines above
4. Test on OpenWRT (device or Docker container)
5. Commit with conventional commit messages
6. Push to your fork: `git push origin feature/your-feature-name`
7. Open a Pull Request against the `dev` branch

### PR Requirements

- Clear description of what the change does
- Reference any related issues
- Tested on OpenWRT (state which version)
- No merge conflicts with `dev` branch

## Testing

CI runs ShellCheck only — it validates syntax and POSIX compliance on every push.
Unit tests and integration tests require a real OpenWrt device and must be run locally.

### Running Tests Locally

```bash
# ShellCheck (mirrors CI)
shellcheck --shell=sh --severity=warning --exclude=SC3043,SC3045 openvpn_server_management.sh

# Unit tests (ShellSpec + busybox ash)
shellspec --shell "busybox sh" spec/unit/

# Integration tests (sexpect on real hardware — authoritative)
OPENWRT_HOST=<device-ip> ./tests/run_tests.sh
```

## Testing Environment

### Real Device (Authoritative)

The authoritative test suite runs on a physical OpenWrt device using `sexpect` to drive
the interactive menu. This is the only way to test package installation, firewall rules,
`crond`, and actual VPN tunnel behaviour.

**Setup requirements:**
- OpenWrt device with SSH key access as root
- `sexpect` and `openssh-sftp-server` installed on the device

**Run from your Mac:**
```bash
OPENWRT_HOST=<device-ip> ./tests/run_tests.sh
```

**How the harness works:**
- `tests/run_tests.sh` — Mac-side launcher: SCPs files, pre-cleans device state (including
  uninstalling packages for Suite 0 cold-start), SSHes in once to run the suite
- `tests/integration_test.sh` — runs ON the device, drives the menu via sexpect
- `tests/sexpect_helper.sh` — primitives: `spawn_script`, `expect_send`, `wait_for`, `send`,
  assertion helpers (`assert_file_exists`, `assert_file_contains`, `assert_file_perms`)
- Output teed to `tests/last_run.txt`

**Best practices for writing sexpect tests:**

1. **Use `expect_send` not `wait_for && send`** — if `wait_for` times out, `&&` silently
   skips the send, leaving the session in an unknown state. `expect_send` hard-fails
   immediately on timeout.

2. **Don't re-wait for the menu prompt in `select_option`** — after each step's final
   `wait_for "Select an option:"`, the cursor is already past the prompt. Calling
   `wait_for` again burns the full timeout. Just `send "$1"` directly.

3. **Use `require_suite` as a gate between suites** — if Suite 0 (package install) fails,
   suites 1–4 will cascade-fail for unrelated reasons. `require_suite` aborts immediately
   with a clear message.

4. **All paths must be variables** — declare all filesystem paths as variables at the top
   of `integration_test.sh` (e.g., `OVPN_EASYRSA`, `OVPN_PKI`, `OVPN_CONF`). Never
   hardcode paths inside test logic or `cleanup()`.

5. **Pre-clean must be complete** — `run_tests.sh` removes all PKI state and uninstalls
   packages before each run. This ensures Suite 0 exercises a real install and Suite 1
   measures real cold-start PKI timing.

6. **apk `pkg_is_installed` pattern** — `apk list --installed` outputs `<name>-<version>`,
   not `<name> <version>`. Use `grep "^<name>-"` not `grep "^<name> "`.

### Docker Container (PKI and Certificate Testing Only)

A Docker-based OpenWRT rootfs container is available for testing:

```bash
# Build the test container
docker build --build-arg SSH_PUBLIC_KEY="$(cat ~/.ssh/id_rsa.pub)" \
  -t openwrt-ovpn-test ./docker

# Run the container
docker run -it --name openwrt-test -p 2222:22 openwrt-ovpn-test

# Connect via SSH (from another terminal)
ssh root@localhost -p 2222

# Copy script to container for testing
scp -P 2222 openvpn_server_management.sh root@localhost:/root/
```

Note: firewall rules, `crond`, service management, and package installation cannot be
tested in Docker. Use a real device for those.

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes to existing functionality
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

Version format: `vMAJOR.MINOR.PATCH` (e.g., `v2.5.0`)

## License

By contributing, you agree that your contributions will be licensed under the GNU General Public License v2.0 (GPL-2.0).

## Questions?

If you have questions or need help, please open an issue on GitHub.
