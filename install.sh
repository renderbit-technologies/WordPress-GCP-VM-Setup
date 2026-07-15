#!/usr/bin/env bash
set -euo pipefail

# Setup script for a new WordPress VM on GCP
# curl -fsSL https://raw.githubusercontent.com/renderbit-technologies/WordPress-GCP-VM-Setup/main/install.sh -o install.sh && sudo bash install.sh

# Run as root on Ubuntu/Debian: sudo bash install.sh
if [ "$(id -u)" -ne 0 ]; then
	echo "Please run as root: sudo $0"
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/setup-swap.sh" ] && [ -f "$SCRIPT_DIR/setup-wp-nginx.sh" ]; then
	# Running from a checkout next to the sub-scripts: use them as-is rather
	# than overwriting local changes with whatever is on GitHub HEAD.
	echo "-----------------------------------------------------"
	echo "Using local deployment scripts from $SCRIPT_DIR"
	echo "-----------------------------------------------------"
	SETUP_SWAP="$SCRIPT_DIR/setup-swap.sh"
	SETUP_WP="$SCRIPT_DIR/setup-wp-nginx.sh"
else
	# Base URL (without commit hash to ensure HEAD/latest version)
	BASE_URL="https://raw.githubusercontent.com/renderbit-technologies/WordPress-GCP-VM-Setup/main"
	TMPDIR=$(mktemp -d)
	trap 'rm -rf "$TMPDIR"' EXIT

	echo "-----------------------------------------------------"
	echo "Fetching latest deployment scripts (HEAD revision)..."
	echo "-----------------------------------------------------"

	# Download to a temp dir so this never touches files in the caller's
	# working directory. This preserves stdin so interactive prompts in the
	# sub-scripts will work.
	curl -fsSL "${BASE_URL}/setup-swap.sh" -o "$TMPDIR/setup-swap.sh"
	curl -fsSL "${BASE_URL}/setup-wp-nginx.sh" -o "$TMPDIR/setup-wp-nginx.sh"

	SETUP_SWAP="$TMPDIR/setup-swap.sh"
	SETUP_WP="$TMPDIR/setup-wp-nginx.sh"
fi

echo "-----------------------------------------------------"
echo "Step 1/2: Setting up Swap"
echo "-----------------------------------------------------"
bash "$SETUP_SWAP"

echo
echo "-----------------------------------------------------"
echo "Step 2/2: Installing WordPress stack"
echo "-----------------------------------------------------"
bash "$SETUP_WP"

echo
echo "-----------------------------------------------------"
echo "All steps completed successfully."
echo "-----------------------------------------------------"
