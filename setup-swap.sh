#!/usr/bin/env bash
set -euo pipefail

# setup-swap.sh
# Configure a swapfile with persistence (User-defined size)

# -------------------------
# Formatting & Logging Helper Functions
# -------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
	echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
	echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
	echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
	echo -e "${RED}[ERROR]${NC} $1"
}

# Error Handler Trap
error_handler() {
	local line_no=$1
	log_error "Script failed at line $line_no."
	exit 1
}
trap 'error_handler ${LINENO}' ERR

# -------------------------
# Root Check
# -------------------------
if [ "$(id -u)" -ne 0 ]; then
	log_error "Please run as root: sudo $0"
	exit 1
fi

echo "-------------------------------------------------------"
log_info "Starting Swap Configuration..."
echo "-------------------------------------------------------"

# Detect RAM and suggest swap size
MEM_MB=$(free -m | awk '/^Mem:/ {print $2}')
DEFAULT_SWAP="2G"

# Simple logic: If RAM > 3.5GB, suggest 4G, else 2G
if [ "$MEM_MB" -gt 3500 ]; then
	DEFAULT_SWAP="4G"
fi

log_info "Detected System RAM: $(free -h | awk '/^Mem:/ {print $2}')"
if [ -z "${SWAP_SIZE:-}" ]; then
	read -rp "Enter swap size (e.g. 1G, 2G, 4G) [${DEFAULT_SWAP}]: " SWAP_SIZE
fi
SWAP_SIZE=${SWAP_SIZE:-$DEFAULT_SWAP}

# 1. Create swap file
if [ -f /swapfile ]; then
	log_warn "/swapfile already exists. Skipping creation."
else
	log_info "Creating ${SWAP_SIZE} swap file..."
	fallocate -l "${SWAP_SIZE}" /swapfile
	log_success "File created."
fi

# 2. Set permissions for the swap file
log_info "Setting permissions (600)..."
chmod 600 /swapfile

# 3. Make it a swap area
if ! file /swapfile | grep -q "swap file"; then
	log_info "Formatting /swapfile as swap area..."
	mkswap /swapfile
else
	log_info "/swapfile is already formatted."
fi

# 4. Enable the swap
if ! swapon --show | grep -q "/swapfile"; then
	log_info "Enabling the swap..."
	swapon /swapfile
	log_success "Swap enabled."
else
	log_info "Swap is already active."
fi

# 5. Make the swap persistent
log_info "Configuring persistence in /etc/fstab..."
if ! grep -q "^/swapfile" /etc/fstab; then
	echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
	log_success "Added fstab entry."
else
	log_info "fstab entry already exists."
fi

# Verify swap usage
echo
log_info "Current Swap Status:"
swapon --show
echo

# 6. Tuning parameters
log_info "Tuning kernel parameters..."
sysctl vm.swappiness=10
sysctl vm.vfs_cache_pressure=50

# 7. Persist tuning
log_info "Updating /etc/sysctl.conf for persistence..."
if ! grep -q "vm.swappiness=10" /etc/sysctl.conf; then
	echo 'vm.swappiness=10' | tee -a /etc/sysctl.conf
fi
if ! grep -q "vm.vfs_cache_pressure=50" /etc/sysctl.conf; then
	echo 'vm.vfs_cache_pressure=50' | tee -a /etc/sysctl.conf
fi

log_success "Swap setup complete!"
