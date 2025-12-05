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

## Testing Environment

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
