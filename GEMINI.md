# Project Overview

**WordPress GCP VM Setup** is a project containing automated, production-ready bash scripts and Ansible playbooks designed to deploy a high-performance, hardened WordPress stack on Google Cloud Platform (or any VM) running **Ubuntu 24.04 LTS**.

The deployed stack consists of:
- **Web Server:** Nginx (Ondrej PPA)
- **PHP:** 8.3 FPM (tuned to available CPU cores with OPcache enabled)
- **Database:** MariaDB with root hardening and a dedicated WP user
- **CMS:** WordPress (latest) installed via WP-CLI
- **Database UI:** phpMyAdmin (latest, auto-configured)
- **TLS:** Certbot / Let's Encrypt with auto-renewal
- **Security:** Fail2Ban (SSH jail), Unattended Upgrades, security headers, XML-RPC mitigation
- **Swap:** Configurable swap file for low-memory VMs
- **Auto-updates:** Weekly WP core/plugin/theme update cron + OS unattended-upgrades

## Building and Running

There are two primary ways to deploy the stack:

### 1. Shell Scripts (`install.sh`, `setup-swap.sh`, `setup-wp-nginx.sh`)
The entry point is `install.sh`. It can be run interactively or non-interactively using environment variables.
```bash
# Non-interactive example
export DOMAIN="example.com" USE_WWW="y" ENABLE_FAIL2BAN="y" CONT="y"
sudo bash install.sh
```

### 2. Ansible Playbook (`ansible/playbook.yml`)
Provides an idempotent and repeatable deployment.
1. Update `ansible/inventory.ini` with target IP and credentials.
2. Run the playbook:
```bash
cd ansible
ansible-playbook -i inventory.ini playbook.yml --extra-vars "domain=example.com use_www=true enable_ssl=true"
```

## Testing

Local testing is facilitated via Vagrant, utilizing disposable VirtualBox VMs.
- **Bash Scripts Testing:** Found in `tests/bash/`.
- **Ansible Playbook Testing:** Found in `ansible/`.
  ```bash
  cd ansible
  vagrant up
  ```

## Development Conventions

- **Shell Scripts Styleguide:**
  - Start with `#!/bin/bash` shebang.
  - Use 2 or 4 spaces for indentation (do not mix tabs and spaces).
  - Use UPPERCASE for exported/global variables, lowercase for local variables.
  - Quote valid references (e.g., `"$VAR"`).
  - Use functions to modularize code.
  - Lint with [ShellCheck](https://www.shellcheck.net/).
- **Testing Changes:** All changes must be tested on a fresh Ubuntu 24.04 LTS VM before submitting pull requests.
- **CI/CD:** GitHub Actions are configured to run ShellCheck, Codacy Security Scans, and Vagrant-based integration tests for both Bash and Ansible changes.
