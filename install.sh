#!/usr/bin/env bash
set -euo pipefail

# Run as root on Ubuntu/Debian: sudo bash install.sh
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

# Base Gist URL (without commit hash to ensure HEAD/latest version)
BASE_URL="https://gist.githubusercontent.com/soham2008xyz/bb3964121c42a87f3f99250edb93c1d9/raw"

echo "-----------------------------------------------------"
echo "Fetching latest deployment scripts (HEAD revision)..."
echo "-----------------------------------------------------"

# Download the files explicitly to disk
# This preserves stdin so interactive prompts in the sub-scripts will work
curl -fsSL "${BASE_URL}/setup-swap.sh" -o setup-swap.sh
curl -fsSL "${BASE_URL}/setup-wp-nginx.sh" -o setup-wp-nginx.sh

# Make them executable
chmod +x setup-swap.sh setup-wp-nginx.sh

echo "-----------------------------------------------------"
echo "Step 1/2: Setting up Swap"
echo "-----------------------------------------------------"
bash ./setup-swap.sh

echo
echo "-----------------------------------------------------"
echo "Step 2/2: Installing WordPress stack"
echo "-----------------------------------------------------"
bash ./setup-wp-nginx.sh

# Cleanup (optional)
# rm setup-swap.sh setup-wp-nginx.sh

echo
echo "-----------------------------------------------------"
echo "All steps completed successfully."
echo "-----------------------------------------------------"