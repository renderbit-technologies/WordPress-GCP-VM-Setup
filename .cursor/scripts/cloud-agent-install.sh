#!/usr/bin/env bash
set -euo pipefail

# Idempotent Cloud Agent install: dev tooling + WordPress test stack.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRED_FILE="/root/.wp-credentials"
DOMAIN="${DOMAIN:-runner.local}"

log() { echo "[cloud-agent-install] $*"; }

configure_test_env() {
	if ! grep -Eq "^[[:space:]]*127\\.0\\.0\\.1[[:space:]].*\\b${DOMAIN}\\b" /etc/hosts; then
		echo "127.0.0.1 ${DOMAIN}" | sudo tee -a /etc/hosts >/dev/null
	fi

	export DOMAIN
	export USE_WWW="${USE_WWW:-n}"
	export WP_DB="${WP_DB:-wp_test}"
	export WP_DB_USER="${WP_DB_USER:-wp_user}"
	export WP_DB_PASS="${WP_DB_PASS:-secure_wp_password}"
	export WP_ADMIN_PASS="${WP_ADMIN_PASS:-secure_admin_password}"
	export MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-secure_root_password}"
	export LE_EMAIL="${LE_EMAIL:-admin@${DOMAIN}}"
	export ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-n}"
	export CONT="${CONT:-y}"
	export SWAP_SIZE="${SWAP_SIZE:-1G}"
	export SKIP_CERTBOT="${SKIP_CERTBOT:-y}"
}

# --- Dev tooling (idempotent) ---
if ! command -v shellcheck >/dev/null 2>&1; then
	log "Installing shellcheck..."
	sudo apt-get update -qq
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y shellcheck
else
	log "shellcheck already installed"
fi

if command -v ansible-galaxy >/dev/null 2>&1; then
	log "Installing Ansible collections..."
	ansible-galaxy collection install -r "${REPO_ROOT}/ansible/collections/requirements.yml" --force-with-deps
else
	log "ansible-galaxy not found; skipping collection install"
fi

# --- WordPress test stack (skip if already provisioned) ---
if [ -f "${CRED_FILE}" ]; then
	log "WordPress stack already provisioned (${CRED_FILE} exists); skipping installation"
	exit 0
fi

configure_test_env
cd "${REPO_ROOT}"

# Container VMs use tini instead of systemd; provide a systemctl shim.
SHIM_DIR="${REPO_ROOT}/.cursor/scripts/shim-bin"
mkdir -p "${SHIM_DIR}"
ln -sf "${REPO_ROOT}/.cursor/scripts/systemctl-shim.sh" "${SHIM_DIR}/systemctl"
chmod +x "${REPO_ROOT}/.cursor/scripts/systemctl-shim.sh"
export PATH="${SHIM_DIR}:${PATH}"

# Swap may be unsupported in containerized Cloud Agent VMs; continue without it.
log "Attempting swap setup (optional in container environments)..."
if ! sudo bash ./setup-swap.sh 2>/dev/null; then
	log "Swap setup skipped (not supported in this environment)"
fi

log "Running setup-wp-nginx.sh..."
sudo env "PATH=${SHIM_DIR}:${PATH}" DOMAIN="${DOMAIN}" USE_WWW="${USE_WWW}" WP_DB="${WP_DB}" \
	WP_DB_USER="${WP_DB_USER}" WP_DB_PASS="${WP_DB_PASS}" WP_ADMIN_PASS="${WP_ADMIN_PASS}" \
	MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS}" LE_EMAIL="${LE_EMAIL}" ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN}" \
	CONT="${CONT}" SKIP_CERTBOT="${SKIP_CERTBOT}" bash ./setup-wp-nginx.sh

# Ensure cron is running before verification (non-systemd containers)
sudo env "PATH=${SHIM_DIR}:${PATH}" systemctl enable --now cron 2>/dev/null || sudo service cron start 2>/dev/null || true

# Disable swap check when swap is unavailable in the container
sudo env "PATH=${SHIM_DIR}:${PATH}" "CHECK_SWAP=n" DOMAIN="${DOMAIN}" WP_DB="${WP_DB}" WP_DB_USER="${WP_DB_USER}" WP_DB_PASS="${WP_DB_PASS}" \
	bash "${REPO_ROOT}/tests/verify-deployment.sh"

log "Install complete"
