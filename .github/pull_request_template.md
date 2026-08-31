# Pull Request

## Summary
<!-- What does this PR change and why? Keep it to 2-4 sentences. -->

## Related issue
<!-- Closes #123 — or `Related to #123` if it does not fully close the issue -->
Closes #

## Type of change
<!-- Check one. Use `x` inside the brackets: [x] -->
- [ ] Bug fix
- [ ] New feature / enhancement
- [ ] Refactor / chore
- [ ] Documentation
- [ ] CI / tooling

## Deployment path
<!-- This repo keeps Bash and Ansible in sync for shared behavior (see CLAUDE.md). Check all that apply. -->
- [ ] Bash scripts (`install.sh`, `setup-swap.sh`, `setup-wp-nginx.sh`)
- [ ] Ansible playbook (`ansible/playbook.yml`, roles `common` → `swap` → `wordpress` → `security`)
- [ ] Documentation / CI only
- [ ] Shared behavior — both paths updated and kept aligned

## Changes
<!-- Bullet list of the concrete changes in this PR -->
-
-
-

## How tested
<!-- How did you verify this? Check what you ran and add commands/output where useful. -->
- [ ] Fresh Ubuntu 24.04 LTS VM (GCP or Vagrant)
- [ ] Bash path: `shellcheck *.sh` — pass
- [ ] Bash path: `cd tests/bash && vagrant up` — pass (or `tests/bash/run-on-runner.sh`)
- [ ] Idempotency: re-ran `vagrant provision` / `sudo bash install.sh` — no drift
- [ ] Ansible path: `ansible-playbook playbook.yml --syntax-check` — pass
- [ ] Ansible path: `cd ansible && vagrant up` — pass
- [ ] SSL skipped for test (`SKIP_CERTBOT=y` / `enable_ssl=false`) where DNS not available

**Test details / evidence:**
<!-- Commands run and relevant output (trim to what matters). e.g. Test domain 192.168.56.10.nip.io, machine type e2-medium -->

```bash

```

## Checklist
- [ ] Both deployment paths stay aligned for shared behavior (or scope is explicitly one path)
- [ ] Idempotent — safe to re-run without credential rotation or breaking existing sites (credential reuse from `/root/.wp-credentials` preserved)
- [ ] No secrets committed (no real passwords, tokens, or `/root/.wp-credentials` contents)
- [ ] Follows shell style (`set -euo pipefail`, quoted `"$VAR"`, `CONTRIBUTING.md` / `.editorconfig`) and Ansible style (`ansible.builtin.*`, descriptive task names, `no_log: true` for secrets)
- [ ] Docs updated if user-facing behavior or variables changed (`README.md`, `ansible/README.md`, env var tables)
- [ ] Linked issue / context and filled in **Type of change** and **Deployment path** above

## Screenshots / logs
<!-- If UI, Nginx, or deployment output is relevant. Redact secrets. -->
