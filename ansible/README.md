# WordPress Ansible Playbook

An Ansible playbook that provisions a complete, production-ready WordPress stack — functionally equivalent to the `setup-swap.sh` and `setup-wp-nginx.sh` bash scripts, with the added benefits of idempotency and repeatability.

## What It Does

The playbook executes four roles in sequence:

### 1. `common` — System Packages

- Updates the `apt` cache (with 1-hour validity window).
- Installs essential system utilities: `curl`, `gnupg2`, `wget`, `htop`, `rsync`, `zip`, `unzip`, `git`, `python3`, `python3-pip`, and others.
- Installs `acl` (required for Ansible `become_user` with unprivileged users).
- Installs `python3-pymysql` (required by the `community.mysql` Ansible collection).

### 2. `swap` — Swap File Management

- Creates a swap file at `/swapfile` (size controlled by `swap_size`, default `2G`).
- Sets swap file permissions to `0600`.
- Formats and enables the swap file, adds it to `/etc/fstab`.
- Tunes sysctl parameters:
  - `vm.swappiness = 10`
  - `vm.vfs_cache_pressure = 50`
- **Idempotent**: skips all steps if the swap file already exists.

### 3. `wordpress` — Full Stack Installation

This is the main role and handles everything from packages to a working WordPress site:

**Package Installation**

- Adds Ondrej PPAs for PHP and Nginx.
- Installs Nginx, MariaDB, PHP 8.3 (FPM, CLI, and extensions: mysql, xml, curl, mbstring, zip, gd, intl, opcache, imagick), Certbot with Nginx plugin.

**PHP-FPM Tuning**

- Calculates pool parameters based on available CPU cores:
  - `pm = dynamic`
  - `pm.max_children = cores × 5` (min 5)
  - `pm.start_servers = cores × 2` (min 2)
  - `pm.min_spare_servers = cores` (min 1)
  - `pm.max_spare_servers = cores × 3` (min 3)
  - `pm.max_requests = 500`
- Sets `listen.owner` and `listen.group` to `www-data`.
- Tunes `php.ini`: `memory_limit = 256M`, `upload_max_filesize = 64M`, `post_max_size = 64M`, `max_execution_time = 300`, `realpath_cache_size = 4096k`, `realpath_cache_ttl = 600`.

**OPcache Configuration**

- Deploys a tuned OPcache config via the `opcache.ini.j2` template:
  - `memory_consumption = 256`, `interned_strings_buffer = 16`, `max_accelerated_files = 10000`, `revalidate_freq = 2`.

**phpMyAdmin**

- Downloads the latest phpMyAdmin release (all-languages zip).
- Extracts to `/usr/share/phpmyadmin`.
- Injects a generated blowfish secret into `config.inc.php`.
- Sets ownership to `www-data` and config permissions to `0640`.
- Creates a writable `tmp/` directory for phpMyAdmin sessions.
- **Idempotent**: skips download if `/usr/share/phpmyadmin` already exists.

**MariaDB Setup & Hardening**

- Creates the WordPress database (`wp_db_name`) and user (`wp_db_user`) with full privileges.
- Removes anonymous MySQL users and drops the `test` database.
- Sets the MySQL root password.
- Creates `/root/.my.cnf` (via `root-my.cnf.j2`) for passwordless root access after initial setup, enabling idempotent re-runs.

**Nginx Configuration**

- Creates the webroot at `/var/www/<domain>` with `www-data` ownership.
- Deploys a security headers snippet (via `security-headers.conf.j2`):
  - `X-Frame-Options: SAMEORIGIN`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer-when-downgrade`
  - `X-XSS-Protection: 1; mode=block`
  - `Content-Security-Policy` with `upgrade-insecure-requests`
- Deploys the Nginx server block (via `nginx-site.conf.j2`) with:
  - WordPress-friendly `try_files` rewrite
  - Blocked access to `wp-config.php`, `readme.html`, `license.txt`, `install.php`, `xmlrpc.php`
  - Static asset caching (`expires max`)
  - phpMyAdmin at `/phpmyadmin`
  - Denied hidden files (dotfiles)
  - Denied PHP execution in `uploads/` and `files/` directories
- Removes the default Nginx site.

**WordPress Installation**

- Installs WP-CLI to `/usr/local/bin/wp`.
- Downloads WordPress core (via `wp core download --skip-content`).
- Generates `wp-config.php` via WP-CLI with the configured database credentials.
- Runs `wp core install` with the configured admin user, password, email, and site URL.
- **Idempotent**: skips download, config, and install if `wp-config.php` already exists.

**WordPress Hardening**

- Injects security constants into `wp-config.php` (via `blockinfile` with markers):
  - `FS_METHOD = 'direct'`
  - `DISALLOW_FILE_EDIT = true`
  - `WP_AUTO_UPDATE_CORE = 'minor'`
  - `FORCE_SSL_ADMIN = true`
  - SSL reverse proxy detection (`HTTP_X_FORWARDED_PROTO`)
- Deploys an MU-plugin (`disable-xmlrpc-pingback.php`) to strip `X-Pingback` headers and disable `pingback.ping`.
- Removes `readme.html` and `license.txt` from the webroot.
- Removes the default `admin` user (if it exists) and reassigns content to the configured admin user.
- Locks `wp-config.php` to mode `0640`.

**Essential Plugins**

Installs (but does not activate) the following plugins:

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

Enables auto-updates for all plugins and themes.

**Weekly Update Cron**

- Deploys a `/etc/cron.weekly/wp-updates` script (via `wp-updates.sh.j2`) that runs `wp core update --minor`, `wp plugin update --all`, and `wp theme update --all`.

**SSL with Certbot**

- Obtains a Let's Encrypt certificate via Certbot (Nginx plugin) with `--redirect` and `--non-interactive`.
- Includes the `www` subdomain if `use_www: true`.
- Enables the `certbot.timer` systemd service for auto-renewal.
- **Conditional**: only runs when `enable_ssl: true` (default). Set `enable_ssl: false` for local/Vagrant testing.
- **Idempotent**: skips if the certificate already exists at `/etc/letsencrypt/live/<domain>/fullchain.pem`.

**Credentials File**

- Saves all generated credentials to `/root/.wp-credentials` (mode `0600`) via the `wp-credentials.j2` template.
- Displays credentials in the Ansible output at the end of the run.

### 4. `security` — Server Hardening

**Unattended Upgrades**

- Installs `unattended-upgrades` and `apt-listchanges`.
- Deploys a configuration (via `50unattended-upgrades.j2`) that:
  - Enables security-only updates (`${distro_id}:${distro_codename}-security`)
  - Sends email notifications only on errors (to `admin_email`)
  - Removes unused kernel packages and dependencies
  - Does **not** auto-reboot
- Enables the periodic apt upgrade timer.

**Fail2Ban**

- Installs and configures Fail2Ban with an SSH jail:
  - `bantime = 1h`, `findtime = 15m`, `maxretry = 5`
- **Conditional**: only runs when `enable_fail2ban: true` (default).

**File Permissions**

- Final permission pass on the WordPress directory:
  - Directories: `0775`
  - Files: `0664`
  - `wp-config.php`: `0640` (owned by `www-data`)

## Playbook Variables

Variables are defined in `playbook.yml` and can be overridden via inventory, command-line (`--extra-vars`), or `vars_prompt`.

### Interactive Prompts (`vars_prompt`)

The playbook prompts for these at runtime. Press Enter to auto-generate a secure 24-character password.

| Prompt                   | Variable          | Default        |
| ------------------------ | ----------------- | -------------- |
| WordPress DB password    | `wp_db_pass`      | Auto-generated |
| WordPress admin password | `wp_admin_pass`   | Auto-generated |
| MySQL root password      | `mysql_root_pass` | Auto-generated |

### Configurable Variables (`vars`)

| Variable          | Description                                 | Default          |
| ----------------- | ------------------------------------------- | ---------------- |
| `domain`          | Domain name for the WordPress site          | `example.com`    |
| `use_www`         | Enable `www.<domain>` as a server alias     | `true`           |
| `wp_db_name`      | WordPress database name                     | `wpdb`           |
| `wp_db_user`      | WordPress database user                     | `wpuser`         |
| `wp_admin_user`   | WordPress admin username                    | `user`           |
| `admin_email`     | Admin email for WordPress and Let's Encrypt | `admin@<domain>` |
| `enable_fail2ban` | Install and enable Fail2Ban                 | `true`           |
| `enable_ssl`      | Obtain SSL certificate via Certbot          | `true`           |
| `swap_size`       | Swap file size                              | `2G`             |

### Auto-Generated Variables (`pre_tasks`)

These are populated automatically and should not be overridden:

| Variable       | Description                                        |
| -------------- | -------------------------------------------------- |
| `pma_blowfish` | Random 32-character blowfish secret for phpMyAdmin |

## Requirements

- **Ansible** 2.9+
- **Target server**: Ubuntu 20.04 / 22.04 / 24.04 (recommended)
- **SSH access** to the target server
- **`community.mysql` collection**:

  ```bash
  ansible-galaxy collection install community.mysql
  ```

## Usage

1. **Update the inventory** — edit `inventory.ini` with your server IP and SSH credentials:

   ```ini
   [wordpress]
   YOUR_SERVER_IP

   [wordpress:vars]
   ansible_user=your_ssh_user
   # ansible_ssh_private_key_file=/path/to/key
   ```

2. **Update playbook variables** — edit the `vars` section of `playbook.yml` or pass overrides:

   ```bash
   ansible-playbook -i inventory.ini playbook.yml \
     --extra-vars "domain=example.com use_www=true enable_ssl=true"
   ```

3. **Run the playbook**:

   ```bash
   ansible-playbook -i inventory.ini playbook.yml
   ```

4. **View credentials** after completion:

   ```bash
   ssh your_server 'sudo cat /root/.wp-credentials'
   ```

## Testing with Vagrant

A `Vagrantfile` is included for local testing using a disposable VM.

### Prerequisites

- [Vagrant](https://developer.hashicorp.com/vagrant/downloads)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

### Setup

1. Navigate to the `ansible` directory:

   ```bash
   cd ansible
   ```

2. Start the Vagrant VM:

   ```bash
   vagrant up
   ```

   This will:
   - Boot an Ubuntu 24.04 VM (`bento/ubuntu-24.04`) with 2 GB RAM and 2 CPUs.
   - Install Ansible on the guest via the `ansible_local` provisioner.
   - Run the playbook with test overrides: domain `192.168.56.10.nip.io`, SSL disabled, test passwords.

3. Access the WordPress site:
   - Open `http://192.168.56.10.nip.io` in your browser.
   - phpMyAdmin: `http://192.168.56.10.nip.io/phpmyadmin`
   - Or map the domain in `/etc/hosts`: `192.168.56.10  192.168.56.10.nip.io`

4. Reprovision (test idempotency):

   ```bash
   vagrant provision
   ```

5. SSH into the VM:

   ```bash
   vagrant ssh
   ```

6. Destroy the VM:

   ```bash
   vagrant destroy -f
   ```

## Directory Structure

```
ansible/
├── ansible.cfg                                     # Ansible settings (pipelining, Python interpreter)
├── inventory.ini                                   # Target host inventory
├── playbook.yml                                    # Main playbook (vars, prompts, role execution)
├── Vagrantfile                                     # Local test VM (Ubuntu 24.04, VirtualBox)
├── README.md                                       # This file
└── roles/
    ├── common/
    │   └── tasks/main.yml                          # apt update, system package installation
    ├── swap/
    │   └── tasks/main.yml                          # Swap file creation, sysctl tuning
    ├── wordpress/
    │   ├── tasks/main.yml                          # Full stack: PHP, Nginx, MariaDB, WP, phpMyAdmin
    │   ├── handlers/main.yml                       # Service restarts (Nginx, PHP-FPM, MariaDB)
    │   ├── files/
    │   │   └── disable-xmlrpc-pingback.php         # MU-plugin for XML-RPC DDoS mitigation
    │   └── templates/
    │       ├── nginx-site.conf.j2                  # Nginx server block with security rules
    │       ├── security-headers.conf.j2            # Nginx security headers snippet
    │       ├── opcache.ini.j2                      # PHP OPcache configuration
    │       ├── root-my.cnf.j2                      # MariaDB root .my.cnf for idempotent re-runs
    │       ├── wp-credentials.j2                   # Credentials file template
    │       └── wp-updates.sh.j2                    # Weekly WP core/plugin/theme update cron script
    └── security/
        ├── tasks/main.yml                          # Unattended Upgrades, Fail2Ban, file permissions
        ├── handlers/main.yml                       # Fail2Ban service restart
        └── templates/
            └── 50unattended-upgrades.j2            # Unattended Upgrades configuration
```

## Benefits Over Bash Scripts

| Feature               | Bash Scripts                  | Ansible Playbook                                   |
| --------------------- | ----------------------------- | -------------------------------------------------- |
| **Idempotency**       | Partial (manual checks)       | Built-in — safe to re-run                          |
| **Readability**       | Shell logic can be complex    | Declarative YAML tasks                             |
| **Multi-server**      | One server at a time          | Inventory-based, run on many                       |
| **Error handling**    | `set -e` + manual traps       | Module-level error reporting                       |
| **Configuration**     | Environment variables         | Variables, prompts, inventories                    |
| **Secret management** | Plaintext env vars            | `vars_prompt` + `no_log`, Ansible Vault compatible |
| **Testing**           | Vagrant + manual verification | Vagrant + `ansible-playbook --check` dry-run       |
