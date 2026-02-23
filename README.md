# WordPress Deployment on GCP

Automated, production-ready scripts and Ansible playbooks to deploy a high-performance, hardened WordPress stack on Google Cloud Platform — optimised for **Ubuntu 24.04 LTS**.

## Stack

| Component        | Details                                                                        |
| ---------------- | ------------------------------------------------------------------------------ |
| **Web server**   | Nginx (Ondrej PPA)                                                             |
| **PHP**          | 8.3 FPM — pool sizing tuned to available CPU cores, OPcache enabled            |
| **Database**     | MariaDB with root hardening and dedicated WP user                              |
| **CMS**          | WordPress (latest) installed via WP-CLI                                        |
| **Database UI**  | phpMyAdmin (latest, auto-configured)                                           |
| **TLS**          | Certbot / Let's Encrypt with auto-renewal                                      |
| **Security**     | Fail2Ban (SSH jail), Unattended Upgrades, security headers, XML-RPC mitigation |
| **Swap**         | Configurable swap file for low-memory VMs                                      |
| **Auto-updates** | Weekly WP core/plugin/theme update cron + OS unattended-upgrades               |

## Prerequisites

- A GCP VM instance (or any Ubuntu server) running **Ubuntu 24.04 LTS**.
- `bash` and `curl` installed (present by default).
- A valid domain name with DNS A record pointing to the VM's external IP.
- GCP VPC firewall rules allowing **TCP 80** and **TCP 443** ingress.

## Quick Start (Shell Scripts)

SSH into your VM and run:

```bash
curl -fsSL https://raw.githubusercontent.com/renderbit-technologies/WordPress-GCP-VM-Setup/main/install.sh -o install.sh && sudo bash install.sh && sudo rm install.sh
```

The script runs in **interactive mode** by default, prompting for:

1. Domain name
2. `www` alias preference
3. Database name and user
4. Admin email (for Let's Encrypt and WordPress)
5. Fail2Ban enable/disable
6. Confirmation to proceed

### Non-Interactive / CI Mode

Set environment variables before running the script to skip prompts:

| Variable          | Description                                    | Default           |
| ----------------- | ---------------------------------------------- | ----------------- |
| `DOMAIN`          | **(Required)** Domain to install WordPress for | —                 |
| `USE_WWW`         | Enable `www` alias (`y`/`n`)                   | `y`               |
| `WP_DB`           | WordPress database name                        | `wpdb`            |
| `WP_DB_USER`      | WordPress database user                        | `wpuser`          |
| `WP_DB_PASS`      | WordPress database password                    | Auto-generated    |
| `WP_ADMIN_PASS`   | WordPress admin password                       | Auto-generated    |
| `MYSQL_ROOT_PASS` | MySQL root password                            | Auto-generated    |
| `LE_EMAIL`        | Email for Let's Encrypt & WP notices           | `admin@$DOMAIN`   |
| `ENABLE_FAIL2BAN` | Enable Fail2Ban (`y`/`n`)                      | `y`               |
| `CONT`            | Skip confirmation prompt (`y`/`n`)             | `y` in batch mode |
| `SWAP_SIZE`       | Swap file size (used by `setup-swap.sh`)       | `2G`              |

Example:

```bash
export DOMAIN="example.com" USE_WWW="y" ENABLE_FAIL2BAN="y"
sudo bash install.sh
```

## Ansible Playbook

An Ansible-based deployment is also available in [`ansible/`](ansible/), offering **idempotent, repeatable** provisioning with the same functionality as the shell scripts.

Roles: `common` → `swap` → `wordpress` → `security`

See the dedicated [Ansible README](ansible/README.md) for full usage, variables, Vagrant testing, and requirements.

## What Gets Installed

### WordPress Hardening

- `wp-config.php` constants: `DISALLOW_FILE_EDIT`, `FS_METHOD = 'direct'`, `FORCE_SSL_ADMIN`, `WP_AUTO_UPDATE_CORE = 'minor'`
- MU-plugin to disable XML-RPC pingback (DDoS mitigation)
- Default `admin` user removed and replaced with a custom admin account
- `readme.html` and `license.txt` removed from webroot
- File permissions hardened: directories `0775`, files `0664`, `wp-config.php` `0640`

### Essential Plugins

The following plugins are automatically installed (not activated — configure per your needs):

- Jetpack, Jetpack Protect, Jetpack Boost
- Akismet Anti-Spam
- AMP
- Sucuri Scanner
- Wordfence Security
- WP Mail SMTP
- Cloudflare Flexible SSL
- Google Analytics for WordPress (MonsterInsights)
- UpdraftPlus Backup
- Better Search Replace

### Nginx Configuration

- Security headers snippet (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `X-XSS-Protection`, `Content-Security-Policy`)
- PHP execution denied in `uploads/` and `files/` directories
- Hidden files (`dotfiles`) denied
- `xmlrpc.php`, `wp-config.php`, `readme.html`, `license.txt`, `install.php` blocked
- Static asset caching with `expires max`
- phpMyAdmin served at `/phpmyadmin`

### Server Security

- **Fail2Ban** — SSH jail with configurable ban time, find time, and max retries
- **Unattended Upgrades** — Automatic OS security patches
- **Certbot** — Automatic HTTPS with Let's Encrypt and systemd renewal timer
- **MariaDB** — Anonymous users removed, test database dropped, root password set

## Repository Structure

```
.
├── install.sh                  # Entrypoint — downloads and runs the setup scripts
├── setup-swap.sh               # Swap file creation and sysctl tuning
├── setup-wp-nginx.sh           # Full WordPress + Nginx + MariaDB + phpMyAdmin setup
├── ansible/                    # Ansible playbook (alternative to shell scripts)
│   ├── playbook.yml            # Main playbook with vars_prompt for credentials
│   ├── inventory.ini           # Target host inventory
│   ├── ansible.cfg             # Ansible configuration
│   ├── Vagrantfile             # Local testing VM (Vagrant + VirtualBox)
│   └── roles/
│       ├── common/             # System packages and apt cache update
│       ├── swap/               # Swap file management
│       ├── wordpress/          # Nginx, PHP, MariaDB, WP-CLI, WordPress, phpMyAdmin
│       └── security/           # Fail2Ban, Unattended Upgrades, file permissions
├── tests/
│   └── bash/                   # Vagrant-based test harness for shell scripts
│       ├── Vagrantfile         # Test VM with env-var driven provisioning
│       └── README.md           # Test harness documentation
├── .github/
│   ├── dependabot.yml          # Dependabot config for GitHub Actions
│   └── workflows/
│       ├── shellcheck.yml      # ShellCheck linting on push/PR
│       ├── codacy.yml          # Codacy security scanning (scheduled + push/PR)
│       ├── bash-test.yml       # Vagrant-based bash script integration test
│       └── ansible-test.yml    # Vagrant-based Ansible playbook integration test
├── CONTRIBUTING.md             # Contribution guidelines and shell script styleguide
├── LICENSE                     # MIT License
└── .codacy.yml                 # Codacy engine configuration (Trivy, Shell)
```

## CI/CD & Quality

| Workflow                  | Trigger                                                     | Description                                                                                              |
| ------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **ShellCheck**            | Push / PR to `main`                                         | Lints all `.sh` files with [ShellCheck](https://www.shellcheck.net/)                                     |
| **Codacy Security Scan**  | Push / PR to `main` + weekly schedule                       | Runs Trivy security analysis and uploads SARIF results                                                   |
| **Bash Scripts Test**     | Push / PR to `main` (when `*.sh` or `tests/bash/**` change) | Provisions a Vagrant VM with the shell scripts, verifies deployment, and tests idempotency               |
| **Ansible Playbook Test** | Push / PR to `main` (when `ansible/**` changes)             | Runs syntax check, provisions a Vagrant VM with the playbook, verifies deployment, and tests idempotency |

## Credentials

After installation, all generated credentials are saved to `~/.wp-credentials` (mode `0600`, owned by `root`). View them with:

```bash
sudo cat ~/.wp-credentials
```

The file contains: MySQL root password, WordPress DB credentials, WordPress admin credentials, phpMyAdmin URL, and PHP-FPM pool tuning parameters.

## Troubleshooting

- **Logs** — Error output is displayed directly on `stdout` during execution. Check console output for failures.
- **DNS** — Ensure DNS A records are propagated before running the script. Certbot will fail otherwise.
- **Firewall** — Verify GCP VPC firewall allows TCP 80 and 443 ingress.
- **Re-run safety** — Both the shell scripts and Ansible playbook are designed to be idempotent; re-running is safe.
- **Credentials file** — If `~/.wp-credentials` exists from a prior run, the script reuses stored credentials.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting bugs, suggesting enhancements, submitting pull requests, and the shell script styleguide.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
