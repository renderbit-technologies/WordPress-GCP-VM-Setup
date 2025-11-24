#!/usr/bin/env bash
set -euo pipefail

# setup-swap.sh
# Configure a 2 GB swapfile with persistence
# Run as root on Ubuntu/Debian: sudo bash setup-swap.sh

# Run as root on Ubuntu/Debian: sudo bash setup-wp-nginx-php8.3-prod.sh
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

# Create a 2 GB swap file
fallocate -l 2G /swapfile

# Set permissions for the swap file
chmod 600 /swapfile

# Make it a swap area
mkswap /swapfile

# Enable the swap
swapon /swapfile

# Make the swap persistent by adding an entry to /etc/fstab
echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab

# Verify swap usage
swapon --show

# Set swappiness parameter
sysctl vm.swappiness=10

# Set vfs_cache_pressure parameter
sysctl vm.vfs_cache_pressure=50

# Add the parameters to /etc/sysctl.conf for persistence
echo 'vm.swappiness=10' | tee -a /etc/sysctl.conf
echo 'vm.vfs_cache_pressure=50' | tee -a /etc/sysctl.conf