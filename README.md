# WordPress Deployment on GCP

## Overview
This repository contains a set of shell scripts optimized for **Ubuntu 24.04 LTS** to deploy a high-performance WordPress stack on Google Cloud Platform (GCP).

The setup includes:
- **Nginx** web server
- **PHP 8.3** (via Ondrej PPA) with FPM and OPcache tuning
- **MariaDB** database server
- **WordPress** (latest) with WP-CLI
- **phpMyAdmin** for database management
- **Swap** memory configuration
- **Fail2Ban** for SSH protection
- **Certbot** for automatic HTTPS (Let's Encrypt)
- Security hardening (permissions, headers, firewall)

## Prerequisites
- A GCP VM instance running **Ubuntu 24.04 LTS**.
- `bash` and `curl` installed on the server (usually present by default).
- A valid domain name pointing to the VM's external IP address.

## Installation
Connect to your GCP VM via SSH and run the following command to start the installation:

```bash
curl -fsSL https://raw.githubusercontent.com/renderbit-technologies/WordPress-GCP-VM-Setup/main/install.sh -o install.sh && sudo bash install.sh && sudo rm install.sh
```

The script will interactively ask for:
1. Domain name
2. Database name and user preferences
3. Admin email for SSL notifications
4. Fail2Ban configuration

## Features
- **Automated Setup**: Installs and configures the entire stack without manual intervention.
- **Performance Tuned**: Configures PHP-FPM and OPcache based on available system resources.
- **Secure**: Implements security headers, file permission hardening, and Fail2Ban.
- **Swap Management**: Automatically detects and configures swap space for stability.
- **Tools Included**: Comes with WP-CLI and phpMyAdmin pre-installed.

## Troubleshooting
- **Logs**: Error logs are directly shown on `stdout` during execution.
- If the setup fails, check the console output for error messages.
- Ensure your DNS records are correctly propagated before running the script (required for SSL generation).

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.