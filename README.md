# WordPress Deployment on GCP

## Overview
This repository contains scripts and guidelines for deploying WordPress on Google Cloud Platform (GCP) using virtual machine instances. This setup allows for a scalable, reliable, and fast WordPress experience.

## Features
- Easy setup with shell scripts
- Customizable VM configurations
- Reliable backup and recovery options
- Support for HTTPS through managed SSL certificates

## Prerequisites
- A Google Cloud Platform account
- Basic knowledge of GCP VM instances and networking
- `gcloud` command-line tool installed and authenticated
- A domain name (optional, but recommended for production)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/renderbit-technologies/WordPress-GCP-VM-Setup.git
   cd WordPress-GCP-VM-Setup
   ```
2. Ensure you have configured the `gcloud` CLI with your GCP project:
   ```bash
   gcloud init
   ```
3. Run the setup script:
   ```bash
   ./setup.sh
   ```

## Configuration
- Edit the `config.sh` file to customize your instance settings, such as:
  - Machine type
  - Zone
  - Disk size
  - WordPress settings

## Usage Instructions for Shell Scripts
- **Setup Script**: `setup.sh`
  - This script provisions the GCP VM instance and installs WordPress automatically.
- **Backup Script**: `backup.sh`
  - Use this script to take backups of your WordPress instance.
- **Restore Script**: `restore.sh`
  - This script helps in restoring your WordPress from a backup.

## Troubleshooting Guide
- If the setup fails, check the GCP console for any VM errors.
- Ensure that your billing account is active with GCP.
- For shell script errors, check the logs generated in the `logs/` directory.

## Contribution Guidelines
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/MyFeature
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add some feature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/MyFeature
   ```
5. Open a pull request.

We're always looking for more contributors! Feel free to add new features, bug fixes, or improvements. Your help is greatly appreciated!

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.