---
description: "Use when editing the bash test harness under tests/bash/**, including the Vagrant harness and hosted-runner integration script. Covers runner assumptions, test-only credentials, and idempotency expectations."
applyTo: "tests/bash/**"
---

# Bash Test Harness Guidelines

- Treat `tests/bash/README.md` as the primary reference for the harness workflow and keep the test harness aligned with the documented commands.
- The harness validates the root-level Bash deployment path only: `setup-swap.sh` followed by `setup-wp-nginx.sh`.
- Preserve the expectation that test runs are non-interactive and self-contained. Test changes should not introduce prompts or external dependencies beyond the documented prerequisites.
- Keep verification logic focused on observable outcomes the harness already uses: HTTP availability and MariaDB access.
- Preserve idempotency coverage. The test flow must continue to support an initial run and a clean rerun without manual cleanup between them.

# Runner Assumptions

- `tests/bash/run-on-runner.sh` is designed for a disposable Ubuntu 24.04 runner and must be executed as root with `sudo`.
- The hosted-runner path appends the test domain to `/etc/hosts`, runs against `127.0.0.1`, and defaults `SKIP_CERTBOT=y` so CI does not require public DNS or Let's Encrypt.
- Keep runner verification tolerant of the current expected responses: HTTP `200` or `301`.
- Avoid adding checks that rely on interactive shells, public DNS, or long-lived machine state.
- The Vagrant path uses VirtualBox, mounts the repo at `/vagrant`, and provisions an Ubuntu 24.04 VM with fixed test values.

# Test-Only Credentials

- Treat all credentials and hostnames in `tests/bash/Vagrantfile` and `tests/bash/run-on-runner.sh` as test-only fixtures.
- Do not replace test defaults with real secrets, production domains, or environment-specific infrastructure details.
- If new environment variables are added to the Bash installer path, update the bash test harness with clearly fake values and document them in `tests/bash/README.md` when needed.
- Keep production guidance out of `tests/bash/**`; this folder should stay focused on isolated validation.

# Validation Flow

- Local Vagrant validation:

  ```bash
  cd tests/bash
  vagrant up
  vagrant provision
  ```

- Hosted-runner style validation on a disposable Ubuntu 24.04 VM:

  ```bash
  sudo bash tests/bash/run-on-runner.sh initial
  sudo bash tests/bash/run-on-runner.sh idempotency
  ```

- When adjusting assertions, keep both flows passing unless the repository’s documented test contract is intentionally being changed.

# Key References

- See `tests/bash/README.md` for local and hosted-runner usage.
- See `tests/bash/run-on-runner.sh` for runner assumptions and verification behavior.
- See `tests/bash/Vagrantfile` for test fixture values and local provisioning behavior.
- See `.github/copilot-instructions.md` for repository-wide rules that still apply alongside this file.
