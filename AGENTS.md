# AGENTS.md

Guidance for coding agents. `CLAUDE.md` is the deepest reference; `ansible/README.md` and
`tests/bash/README.md` cover their harnesses; `.github/instructions/` holds scoped rules for
`install.sh`/`setup-*.sh`, `ansible/**` and `tests/bash/**`.

## What this repo is

Production provisioning for one WordPress stack, implemented twice:

- Root Bash: `install.sh` orchestrates `setup-swap.sh` -> `setup-wp-nginx.sh` -> `setup-ops-agent.sh`
- `ansible/playbook.yml`: roles `common` -> `swap` -> `wordpress` -> `security` -> `ops_agent`

Both paths must produce the same box. Shared behavior (hardening, Nginx rules, PHP tuning,
credentials, cron) belongs in both unless the request is explicitly scoped to one path. Only
Ubuntu 24.04 (`noble`) and 26.04 (`resolute`) are supported; both paths fail fast otherwise.

## Validate like CI

```bash
shellcheck $(git ls-files '*.sh')   # CI lints every tracked .sh, not just root scripts
```

```bash
cd ansible
cp inventory.ini.example inventory.ini   # gitignored, so no inventory ships; every ansible command needs one
ansible-galaxy collection install -r collections/requirements.yml
ansible-playbook playbook.yml --syntax-check
```

Vagrant integration tests need VirtualBox with nested virtualization and are slow (CI budgets 75
minutes per job); if unavailable, say the check was skipped instead of guessing at correctness.

```bash
cd tests/bash && vagrant up && vagrant provision   # Bash path
cd ansible    && vagrant up && vagrant provision   # Ansible path
```

Export `UBUNTU_VERSION=26.04` on *every* `vagrant up|provision|ssh` call, not just the first, or
Vagrant re-evaluates against the default 24.04 box.

No virtualization, but a disposable Ubuntu VM available:

```bash
sudo bash tests/bash/run-on-runner.sh initial
sudo bash tests/bash/run-on-runner.sh idempotency
```

`tests/verify-deployment.sh` is the single definition of "deployed correctly" (rendered front page,
`wp-login.php`, phpMyAdmin, blocked sensitive paths, >1MB uploads, OPcache, swap, `0600` credential
file). Re-run it after provisioning (`DOMAIN=<domain> sudo -E bash tests/verify-deployment.sh`)
rather than inventing ad-hoc curls.

## Gotchas

- **Credentials are reused, never rotated.** Both paths read `/root/.wp-credentials` and keep the
  live DB/root/admin passwords on re-run. Blank prompt answers on a re-run are correct behavior,
  not a bug to fix.
- **The playbook has `vars_prompt`**, so unattended runs silently take the blank defaults and
  auto-generate. Pass `-e wp_db_pass=... -e wp_admin_pass=... -e mysql_root_pass=...` to control them.
- **PHP comes only from `packages.sury.org/php`** on both releases. `ppa:ondrej/php` is frozen.
  Re-runs migrate 24.04 sites off it: install `debsuryorg-repository-php`, then remove the PPA.
- **In the PHP repository step, skip `php.list` when `php.sources` exists.** Apt fails on two
  entries for one repository with different `signed-by` keyrings.
- **In the PHP repository step, keep `/usr/share/keyrings/deb.sury.org-php.gpg`.** The
  `debsuryorg-archive-keyring` package owns it.
- **`ansible/Vagrantfile` does not use `inventory.ini`**: it provisions with `ansible_local` and
  inline `extra_vars`, and syncs `../tests` to `/vagrant-tests`. The Ansible harness breaks if
  `tests/verify-deployment.sh` or `tests/vagrant/configure-apt-mirror.sh` moves.
- **CI path filters are narrow.** `bash-test.yml` runs on root `*.sh`, `tests/bash/**`,
  `tests/vagrant/**`, `tests/verify-deployment.sh`; `ansible-test.yml` on `ansible/**` plus those
  shared `tests/` files. Touching only `docs/` or instruction files runs no test at all.
- **`install.sh` prefers local scripts but otherwise downloads `main` HEAD.** A fix that exists only
  in a checkout never reaches a VM provisioned with the one-liner.
- **`.agents/skills/**` is vendored**: hash-pinned in `skills-lock.json` and symlinked from ~14 agent
  dotdirs (`.claude/skills`, `.cursor/skills`, ...). Fix upstream, not here. Same for
  `.github/instructions/codacy.instructions.md`, which is generated and gitignored.
- Never commit secrets or a real `ansible/inventory.ini`; `inventory.ini.example` is the tracked
  template, and credentials in `tests/bash/Vagrantfile` are fixtures.
- Docs drift from the code (`README.md`, `GEMINI.md`, `.github/copilot-instructions.md`, and
  `.github/instructions/` predate the `ops_agent` role). Trust the scripts and the playbook over prose.
