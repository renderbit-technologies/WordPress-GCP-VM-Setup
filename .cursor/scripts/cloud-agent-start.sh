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

ensure_mysql_socket() {
	# PHP defaults to /var/run/mysqld/mysqld.sock; MariaDB may use /run/mysqld.
	mkdir -p /var/run/mysqld
	if [ -S /run/mysqld/mysqld.sock ] && [ ! -e /var/run/mysqld/mysqld.sock ]; then
		ln -sf /run/mysqld/mysqld.sock /var/run/mysqld/mysqld.sock
		log "Linked MySQL socket for PHP compatibility"
	fi
}

wait_for_mysql() {
	for _ in $(seq 1 30); do
		if mysqladmin ping --silent 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	log "Warning: MariaDB did not become ready in time"
	return 1
}

# Only start services if the stack was provisioned
if [ ! -f "${CRED_FILE}" ]; then
	log "WordPress stack not yet provisioned; skipping service startup"
	exit 0
fi

for svc in mariadb cron nginx php8.4-fpm; do
	start_service "${svc}"
done

ensure_mysql_socket
wait_for_mysql || true

# php8.4-fpm may need manual start if init script name differs
if ! pgrep -f "php-fpm: master" >/dev/null 2>&1; then
	php-fpm8.4 --daemonize 2>/dev/null || /usr/sbin/php-fpm8.4 --daemonize 2>/dev/null || true
	log "Started php8.4-fpm manually"
fi

log "Startup complete"
