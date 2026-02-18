# WordPress Ansible Playbook

This directory contains an Ansible playbook that replicates the functionality of the `setup-swap.sh` and `setup-wp-nginx.sh` bash scripts.

## Overview

The bash scripts perform the following tasks:
1.  **System Setup**: Create swap file, configure sysctl settings.
2.  **Stack Installation**: Install Nginx, PHP 8.3, MariaDB, Certbot.
3.  **WordPress Setup**: Download WP via WP-CLI, configure DB, generate wp-config.php.
4.  **Security**: Configure Fail2Ban, Unattended Upgrades, Secure file permissions.
5.  **SSL**: Obtain Let's Encrypt certificate.

This Ansible playbook maps these tasks to roles:
-   **common**: Updates apt cache, installs basic utilities.
-   **swap**: Handles swap creation and persistence (maps to `setup-swap.sh`).
-   **wordpress**: Handles Nginx, PHP, MariaDB, WP installation and configuration (maps to `setup-wp-nginx.sh`).

## Benefits of Ansible over Bash Scripts

-   **Idempotency**: Ansible modules are designed to be idempotent. Running the playbook multiple times won't break things (e.g., won't create swap if it already exists, won't reinstall packages).
-   **Readability**: YAML syntax is often easier to read and maintain than complex bash logic.
-   **Centralized Management**: Easily manage multiple servers with different inventories.
-   **Error Handling**: Ansible provides better error reporting and handling out of the box.

## Requirements

-   Ansible 2.9+
-   Target server (Ubuntu 20.04/22.04/24.04 recommended)
-   SSH access to the target server
-   `community.mysql` collection (for database tasks):
    ```bash
    ansible-galaxy collection install community.mysql
    ```

## Usage

1.  Update `inventory.yml` with your server IP/hostname.
2.  Update `playbook.yml` variables (domain, db_name, etc.).
3.  Run the playbook:
    ```bash
    ansible-playbook -i inventory.yml playbook.yml
    ```
