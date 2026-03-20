# Project Guidelines

## Architecture

- This repository maintains two deployment paths for the same Ubuntu 24.04 WordPress stack: root-level Bash scripts and the Ansible playbook under `ansible/`.
- The Bash entrypoint is `install.sh`, which orchestrates `setup-swap.sh` and `setup-wp-nginx.sh`.
- The Ansible playbook runs roles in a fixed sequence: `common` -> `swap` -> `wordpress` -> `security`.
- When changing shared behavior, keep the Bash and Ansible implementations aligned unless the task is explicitly scoped to one path.

## Code Style

- Follow `.editorconfig`: spaces, LF line endings, UTF-8, and 2-space indentation by default. PHP files use 4 spaces.
- For shell scripts, follow the style guide in `CONTRIBUTING.md`: use `#!/bin/bash`, quote variable expansions, use uppercase for exported or global variables, and keep local variables lowercase.
- Prefer small, idempotent changes. Re-runs are expected to be safe for both the scripts and the playbook.

## Build And Test

- For shell changes, run ShellCheck when available and validate on Ubuntu 24.04 using the bash harness in `tests/bash/README.md`.
- For Ansible changes, run `ansible-playbook --syntax-check` when possible and validate with the workflow described in `ansible/README.md`.
- CI covers ShellCheck, Codacy security scanning, bash integration tests, and Ansible integration tests. Match those expectations before proposing a change.
- Certbot and live DNS are external dependencies. Use the documented test modes such as `SKIP_CERTBOT=y` or `enable_ssl=false` for CI and local validation where public DNS is unavailable.

## Conventions

- Treat Ubuntu 24.04 as the supported target unless the task explicitly broadens compatibility.
- Preserve the current credential and secret handling model: generated values may be reused on reruns from the stored credentials files.
- Keep environment variable names for the Bash path and variable names for the Ansible path consistent with the documented interfaces in the existing READMEs.
- Do not duplicate long setup tables or role-by-role explanations in agent responses; link to the existing documentation instead.

## Key References

- `README.md`: deployment overview, non-interactive environment variables, CI summary, and troubleshooting.
- `CONTRIBUTING.md`: contribution process, shell script style guide, and testing expectations.
- `ansible/README.md`: playbook variables, role behavior, Vagrant workflow, and Ansible-specific validation.
- `tests/bash/README.md`: bash test harness, hosted-runner flow, and test-only environment values.
- `GEMINI.md`: concise AI-oriented project summary.
