#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "Please run as root: sudo $0"
	exit 1
fi

MODE="${1:-initial}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DOMAIN="${DOMAIN:-runner.local}"

append_host_entry() {
	local host_name=$1

	if ! grep -Eq "^[[:space:]]*127\\.0\\.0\\.1[[:space:]].*\\b${host_name}\\b" /etc/hosts; then
		echo "127.0.0.1 ${host_name}" >>/etc/hosts
	fi
}

configure_test_env() {
	append_host_entry "${DOMAIN}"

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

verify_installation() {
	echo "Verifying HTTP response..."
	HTTP_CODE="$(curl -s -o /dev/null -w "%{http_code}" -H "Host: ${DOMAIN}" http://127.0.0.1)"

	if [[ "${HTTP_CODE}" != "200" && "${HTTP_CODE}" != "301" ]]; then
		echo "Expected WordPress to return HTTP 200 or 301, got ${HTTP_CODE}"
		exit 1
	fi

	echo "Verifying database access..."
	mysql -u "${WP_DB_USER}" "-p${WP_DB_PASS}" -h localhost -e "USE \`${WP_DB}\`;"
}

run_installation() {
	echo "Running setup-swap.sh on the hosted runner..."
	bash ./setup-swap.sh

	echo "Running setup-wp-nginx.sh on the hosted runner..."
	bash ./setup-wp-nginx.sh
}

configure_test_env
cd "${REPO_ROOT}"

case "${MODE}" in
	initial)
		run_installation
		verify_installation
		echo "Hosted runner initial integration test completed successfully."
		;;
	idempotency)
		echo "Re-running scripts to verify idempotency..."
		run_installation
		verify_installation
		echo "Hosted runner idempotency check completed successfully."
		;;
	*)
		echo "Unsupported mode: ${MODE}"
		echo "Usage: sudo bash tests/bash/run-on-runner.sh [initial|idempotency]"
		exit 1
		;;
esac
