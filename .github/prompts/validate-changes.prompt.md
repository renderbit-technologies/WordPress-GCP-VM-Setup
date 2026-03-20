---
name: "Validate Changes"
description: "Run the correct validation checks for changed files in this repository by choosing between root Bash script checks, bash test harness checks, and Ansible checks."
argument-hint: "Optional: specific files, folders, or a validation scope to focus on"
agent: "agent"
---

Validate the current changes in this repository.

Use this routing logic:

1. Determine the target files.
   - If the user provided files or a scope, use that.
   - Otherwise inspect the current staged and unstaged git changes.

2. Classify the changed files.
   - Root Bash scripts: `install.sh`, `setup-*.sh`
   - Bash test harness: `tests/bash/**`
   - Ansible: `ansible/**`

3. Run the matching validation flow.
   - If multiple categories changed, run all relevant flows.
   - Start with the lightest checks first, then heavier environment checks.
   - Do not run unrelated validation flows.

Validation flows:

## Root Bash scripts

- Run ShellCheck on changed root shell scripts when available.
- If the environment supports it, validate via the bash harness documented in [tests/bash/README.md](../../tests/bash/README.md).
- For CI-style validation without public DNS, prefer the hosted-runner path and keep Certbot skipped through `SKIP_CERTBOT=y`.

## Bash test harness

- Validate `tests/bash/**` changes using the harness contract in [tests/bash/README.md](../../tests/bash/README.md).
- Local flow:

  ```bash
  cd tests/bash
  vagrant up
  vagrant provision
  ```

- Hosted-runner style flow on disposable Ubuntu 24.04:

  ```bash
  sudo bash tests/bash/run-on-runner.sh initial
  sudo bash tests/bash/run-on-runner.sh idempotency
  ```

## Ansible

- Run the repository syntax check first:

  ```bash
  cd ansible
  cp inventory.ini.example inventory.ini
  ansible-galaxy collection install community.mysql
  ansible-playbook playbook.yml --syntax-check
  ```

- If the environment supports it, run the Vagrant validation flow:

  ```bash
  cd ansible
  vagrant up
  vagrant ssh -c "curl -I http://localhost"
  vagrant provision
  vagrant ssh -c "curl -I http://localhost"
  ```

Execution rules:

- Follow the scoped instruction files already present in the workspace for `install.sh`, `setup-*.sh`, `tests/bash/**`, and `ansible/**`.
- Reuse existing repo conventions instead of inventing new checks.
- If a required tool or environment is unavailable, state that clearly and mark the check as skipped rather than failed.
- If a check fails, report the exact failing command, the relevant file set, and the most likely next fix.

Return the result in this format:

## Validation Summary
- Scope: ...
- Routed checks: ...

## Results
- Passed: ...
- Failed: ...
- Skipped: ...

## Notes
- Mention missing tools, environment limitations, or follow-up actions.