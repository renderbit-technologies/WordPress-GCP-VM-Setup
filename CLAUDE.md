# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository maintains two deployment paths for a production-ready WordPress stack on Ubuntu 24.04 LTS:

- **Bash scripts**: Root-level scripts for interactive or CI deployment
- **Ansible playbook**: Idempotent, repeatable provisioning in `ansible/`

The stack includes: Nginx (Ondrej PPA), PHP 8.4 FPM, MariaDB, WordPress (latest), phpMyAdmin, Certbot (Let's Encrypt), Fail2Ban, and unattended upgrades.

## Command Reference

### Development & Testing

**Shell script validation:**

```bash
# Lint with ShellCheck (if available)
shellcheck *.sh

# Run full integration test with Vagrant
cd tests/bash && vagrant up

# Test idempotency
vagrant provision

# Cleanup
cd tests/bash && vagrant destroy -f

# Hosted-runner style test (disposable Ubuntu VM)
sudo bash tests/bash/run-on-runner.sh initial
sudo bash tests/bash/run-on-runner.sh idempotency
```

**Ansible validation:**

```bash
# Install required collection
ansible-galaxy collection install community.mysql

# Syntax check
cd ansible && ansible-playbook playbook.yml --syntax-check

# Full local test with Vagrant
cd ansible && vagrant up

# Test idempotency
vagrant provision

# Cleanup
cd ansible && vagrant destroy -f
```

**CI workflows** (see `.github/workflows/`):

- `shellcheck.yml`: Lints all `.sh` files on push/PR
- `bash-test.yml`: Vagrant-based integration test for shell scripts
- `ansible-test.yml`: Vagrant-based integration test for Ansible playbook
- `codacy.yml`: Security scanning with Trivy

### Deployment

**Bash path (interactive):**

```bash
sudo bash install.sh
```

**Bash path (non-interactive):**

```bash
export DOMAIN="example.com" USE_WWW="y" ENABLE_FAIL2BAN="y"
sudo bash install.sh
```

**Ansible path:**

```bash
cd ansible
# Update inventory.ini with your server IP and SSH credentials
ansible-playbook -i inventory.ini playbook.yml
```

View credentials after deployment:

```bash
sudo cat /root/.wp-credentials
```

## Architecture & Structure

### Dual Deployment Paths

The repository maintains **two parallel implementations** that must stay aligned when changing shared behavior:

**Bash scripts** (root-level):

- Entry: `install.sh` → orchestrates `setup-swap.sh` + `setup-wp-nginx.sh`
- Direct system commands, environment variable configuration
- Interactive prompts *or* environment variables for non-interactive mode
- Credentials stored in `/root/.wp-credentials` (mode `0600`)

**Ansible playbook** (`ansible/`):

- Entry: `playbook.yml` → roles: `common` → `swap` → `wordpress` → `security`
- Idempotent, declarative tasks with Jinja2 templates
- `vars_prompt` for credentials (auto-generates secure passwords)
- Same credential file format as Bash path

When modifying shared functionality (e.g., WordPress hardening, Nginx config, PHP tuning), **update both paths** unless the task is explicitly scoped to one path.

### Key Components

**Swap Management**:

- Script: `setup-swap.sh` or Ansible `swap` role
- Creates `/swapfile` (default `2G`, configurable via `SWAP_SIZE`/`swap_size`)
- Tunes `vm.swappiness=10` and `vm.vfs_cache_pressure=50`
- Idempotent: skips if swap file exists

**WordPress Stack** (`setup-wp-nginx.sh` or `wordpress` role):

1. **Packages**: Ondrej PPAs → Nginx, MariaDB, PHP 8.4 FPM + extensions
2. **PHP-FPM Tuning**: Dynamic pool sizing based on CPU cores (`pm.max_children = cores × 5`)
3. **OPcache**: 256MB memory, 10K accelerated files
4. **MariaDB**: Creates WP database/user, removes anonymous users, sets root password
5. **Nginx**: Security headers, blocked paths (`wp-config.php`, `xmlrpc.php`), static asset caching
6. **WordPress**: WP-CLI installation, `wp-config.php` with hardening constants, removes default `admin` user
7. **phpMyAdmin**: Latest release, configured blowfish secret, served at `/phpmyadmin`
8. **SSL**: Certbot with Nginx plugin (skippable via `SKIP_CERTBOT=y`/`enable_ssl=false`)
9. **Credentials**: Saved to `/root/.wp-credentials` with all generated passwords and phpMyAdmin URL
10. **Weekly Cron**: Updates WP core (minor), plugins, themes

**Security Hardening** (Ansible `security` role or inline in `setup-wp-nginx.sh`):

- Fail2Ban SSH jail (`bantime=1h`, `findtime=15m`, `maxretry=5`)
- Unattended upgrades (security patches only, no auto-reboot)
- File permissions: directories `0775`, files `0664`, `wp-config.php` `0640`
- WordPress: MU-plugin disables XML-RPC pingback, security constants in `wp-config.php`

### Template & Configuration Files

**Ansible templates** (`ansible/roles/*/templates/`):

- `nginx-site.conf.j2`: Nginx server block with WordPress rewrites, security blocks
- `security-headers.conf.j2`: Security headers snippet
- `opcache.ini.j2`: PHP OPcache configuration
- `root-my.cnf.j2`: MariaDB root credentials for idempotent re-runs
- `wp-credentials.j2`: Credential file template (matches Bash format)
- `wp-updates.sh.j2`: Weekly cron script for WP updates
- `50unattended-upgrades.j2`: Unattended upgrades config

**Files referenced by both paths**:

- `ansible/roles/wordpress/files/disable-xmlrpc-pingback.php`: MU-plugin for XML-RPC mitigation

## Conventions & Code Style

### Shell Scripts

- **Shebang**: `#!/usr/bin/env bash` or `#!/bin/bash`
- **Safety**: `set -euo pipefail` at the top of every script
- **Variables**: UPPERCASE for exported/global, lowercase for local
- **Quotes**: Always quote variable expansions (`"$VAR"`)
- **Logging**: Use existing helper functions (`log_info`, `log_success`, `log_warn`, `log_error`)
- **Idempotency**: Check for existing state before making changes (e.g., swap file, `wp-config.php`, certificates)

### Ansible

- **Modules**: Prefer `ansible.builtin.*`
- **Naming**: Use descriptive task names for readable play output
- **Idempotency**: Leverage module idempotency; use `creates:`/`removes:` where needed
- **Secrets**: Use `no_log: true` for tasks handling credentials
- **Variables**: Preserve variable names from `playbook.yml` and `ansible/README.md`
- **Handlers**: Use for service restarts; notify instead of unconditional restarts

### Testing Credentials

**Test-only values** (never use in production):

- Vagrant domain: `192.168.56.10.nip.io` or `vagrant.local`
- MySQL root: `secure_root_password`
- WP database: `wp_test` or `wpdb`
- WP user: `wp_user` or `wpuser`
- WP admin: `user` / `secure_admin_password`

**Production variables** (documented in README):

- `DOMAIN`: Required, determines webroot and certificate
- `USE_WWW`: `y/n` (default: `y`)
- `WP_DB`: Database name (default: `wpdb`)
- `WP_DB_USER`: Database user (default: `wpuser`)
- `WP_DB_PASS`: Auto-generated if not set
- `WP_ADMIN_PASS`: Auto-generated if not set
- `MYSQL_ROOT_PASS`: Auto-generated if not set
- `LE_EMAIL`: Admin email (default: `admin@$DOMAIN`)
- `ENABLE_FAIL2BAN`: `y/n` (default: `y`)
- `SKIP_CERTBOT`: `y` to skip SSL for CI/tests (default: `n`)
- `SWAP_SIZE`: Swap file size (default: `2G`)
- `CONT`: `y` to skip confirmation prompts in batch mode

## Environment-Specific Behavior

**DNS Requirements**:

- Production: Requires valid domain with DNS A record pointing to VM IP. Certbot will fail otherwise.
- Vagrant: Uses `192.168.56.10.nip.io` or maps to `/etc/hosts`
- CI/Hosted-runner: Maps domain to `127.0.0.1`, sets `SKIP_CERTBOT=y`

**Credential Reuse**:

- If `/root/.wp-credentials` exists, scripts reuse stored credentials instead of regenerating
- This enables safe re-runs and idempotency

**SSL/TLS**:

- Production: Certbot with Let's Encrypt, auto-renewal via systemd timer
- Testing: Skip with `SKIP_CERTBOT=y` (Bash) or `enable_ssl=false` (Ansible)

## Critical Implementation Notes

### WordPress Hardening Alignment

Both Bash and Ansible paths implement identical hardening:

- `wp-config.php` constants: `DISALLOW_FILE_EDIT`, `FS_METHOD='direct'`, `FORCE_SSL_ADMIN`, `WP_AUTO_UPDATE_CORE='minor'`
- MU-plugin: `disable-xmlrpc-pingback.php` removes `X-Pingback` header and disables `pingback.ping`
- Removed files: `readme.html`, `license.txt` from webroot
- Default `admin` user removed and replaced with configured admin

### Nginx Security Configuration

The Nginx configuration (identical in both paths) includes:

- Security headers: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `X-XSS-Protection`, `Content-Security-Policy`
- Blocked paths: `wp-config.php`, `xmlrpc.php`, `readme.html`, `license.txt`, `install.php`, hidden files
- PHP execution denied in `uploads/` and `files/`
- Static asset caching with `expires max`
- phpMyAdmin at `/phpmyadmin`

### PHP-FPM Pool Sizing Formula

Pool parameters scale with CPU cores (`cores`):

- `pm = dynamic`
- `pm.max_children = cores × 5` (minimum 5)
- `pm.start_servers = cores × 2` (minimum 2)
- `pm.min_spare_servers = cores` (minimum 1)
- `pm.max_spare_servers = cores × 3` (minimum 3)
- `pm.max_requests = 500`

This formula ensures optimal resource utilization based on available CPU.

## References

- `README.md`: Stack details, environment variables, CI workflows
- `CONTRIBUTING.md`: Contribution process, shell script style guide
- `ansible/README.md`: Playbook variables, Vagrant workflow, role behavior
- `tests/bash/README.md`: Test harness usage, runner assumptions
- `.github/copilot-instructions.md`: Repository-wide coding rules
- `.editorconfig`: Indentation, line endings, encoding
