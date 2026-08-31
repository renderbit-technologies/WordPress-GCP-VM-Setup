#!/usr/bin/env bash
set -euo pipefail

# Per-boot startup: ensure hosts entry and WordPress services are running.
DOMAIN="${DOMAIN:-runner.local}"
CRED_FILE="/root/.wp-credentials"

log() { echo "[cloud-agent-start] $*"; }

append_host_entry() {
	if ! grep -Eq "^[[:space:]]*127\\.0\\.0\\.1[[:space:]].*\\b${DOMAIN}\\b" /etc/hosts; then
		echo "127.0.0.1 ${DOMAIN}" >>/etc/hosts
		log "Added /etc/hosts entry for ${DOMAIN}"
	fi
}

start_service() {
	local svc=$1
	if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1; then
		systemctl is-active --quiet "${svc}" || systemctl start "${svc}"
		log "Service ${svc} is active"
	fi
}

append_host_entry

# Container VMs use tini instead of systemd; provide a systemctl shim.
SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/shim-bin"
mkdir -p "${SHIM_DIR}"
ln -sf "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/systemctl-shim.sh" "${SHIM_DIR}/systemctl"
chmod +x "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/systemctl-shim.sh"
export PATH="${SHIM_DIR}:${PATH}"

# Only start services if the stack was provisioned
if [ ! -f "${CRED_FILE}" ]; then
	log "WordPress stack not yet provisioned; skipping service startup"
	exit 0
fi

for svc in nginx mariadb php8.4-fpm cron; do
	start_service "${svc}"
done

# php8.4-fpm may need manual start if init script name differs
if ! pgrep -f "php-fpm: master" >/dev/null 2>&1; then
	php-fpm8.4 --daemonize 2>/dev/null || /usr/sbin/php-fpm8.4 --daemonize 2>/dev/null || true
	log "Started php8.4-fpm manually"
fi

log "Startup complete"
