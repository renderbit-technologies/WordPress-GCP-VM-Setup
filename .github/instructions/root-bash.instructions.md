---
description: "Use when editing the root Bash deployment scripts such as install.sh, setup-swap.sh, and setup-wp-nginx.sh. Covers shell-specific editing rules, non-interactive environment variable compatibility, and script validation without test-harness details."
applyTo: "install.sh, setup-*.sh"
---

# Root Bash Script Guidelines

- Treat `install.sh` as a thin orchestrator for `setup-swap.sh` and `setup-wp-nginx.sh`. Keep deployment logic in the setup scripts unless orchestration behavior itself is changing.
- Keep the Bash deployment path aligned with the Ansible path when shared behavior changes, unless the task is explicitly Bash-only.
- Preserve the current script shape: root check first, `set -euo pipefail`, readable logging, and early failure on invalid conditions.
- Follow the shell conventions from `CONTRIBUTING.md`: `#!/bin/bash` or the existing shebang style, quoted expansions, uppercase exported/global variables, and lowercase local variables.
- Prefer small, idempotent shell changes. Re-running the scripts should remain safe for swap setup, package installation, credentials reuse, WordPress bootstrap, and service configuration.

# Interface Compatibility

- Preserve documented environment variable names and meanings such as `DOMAIN`, `USE_WWW`, `WP_DB`, `WP_DB_USER`, `WP_DB_PASS`, `WP_ADMIN_PASS`, `MYSQL_ROOT_PASS`, `LE_EMAIL`, `ENABLE_FAIL2BAN`, `CONT`, `SWAP_SIZE`, and `SKIP_CERTBOT`.
- Keep interactive and non-interactive flows compatible. If a variable is part of the documented interface, do not silently repurpose it or change its default behavior without updating documentation and the test harness.
- Preserve the current credential reuse model through the stored credentials file rather than regenerating secrets on every rerun.
- When adding new script inputs, make them work in both prompt-driven and environment-variable-driven execution.

# Script Structure

- Keep logging and error handling consistent with the existing helper functions in the setup scripts.
- Prefer extracting shell logic into small helper functions over growing long inline blocks.
- When changing service configuration, keep script-side verification and restart behavior targeted rather than restarting everything unconditionally.
- Keep external dependencies explicit. For CI-style and local validation without public DNS, continue supporting `SKIP_CERTBOT=y` instead of requiring live certificate issuance.

# Validation Flow

- Lint root shell scripts with ShellCheck when available.
- Validate script changes using the bash harness documented in `tests/bash/README.md`.
- For CI-style validation without public DNS, use the existing hosted-runner path and keep Certbot skipped through `SKIP_CERTBOT=y`.

# Key References

- See `README.md` for the documented non-interactive environment variables and deployment flow.
- See `CONTRIBUTING.md` for shell style and testing expectations.
- See `tests/bash/README.md` for validation commands and harness usage.
- See `.github/copilot-instructions.md` for repository-wide rules that still apply alongside this file.
