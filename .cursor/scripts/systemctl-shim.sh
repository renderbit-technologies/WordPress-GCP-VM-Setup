#!/usr/bin/env bash
# systemctl shim for container environments without systemd (Cloud Agent VMs).
set -euo pipefail

cmd="${1:-}"
shift || true

start_svc() {
	local svc=$1
	service "${svc}" start 2>/dev/null || "/etc/init.d/${svc}" start
}

run_svc_cmd() {
	local svc=$1
	local action=$2
	service "${svc}" "${action}" 2>/dev/null || "/etc/init.d/${svc}" "${action}"
}

svc_from_unit() {
	local unit=$1
	echo "${unit%.service}"
}

case "${cmd}" in
	enable)
		unit=""
		do_start=0
		while [ $# -gt 0 ]; do
			case "$1" in
				--now) do_start=1 ;;
				*) unit="$1" ;;
			esac
			shift
		done
		[ -n "${unit}" ] || exit 0
		svc=$(svc_from_unit "${unit}")
		update-rc.d "${svc}" defaults 2>/dev/null || true
		if [ "${do_start}" -eq 1 ]; then
			start_svc "${svc}"
		fi
		;;
	start|restart|reload)
		unit="${1:-}"
		[ -n "${unit}" ] || exit 0
		svc=$(svc_from_unit "${unit}")
		run_svc_cmd "${svc}" "${cmd}"
		;;
	stop)
		unit="${1:-}"
		[ -n "${unit}" ] || exit 0
		svc=$(svc_from_unit "${unit}")
		service "${svc}" stop 2>/dev/null || "/etc/init.d/${svc}" stop 2>/dev/null || true
		;;
	is-active)
		unit=""
		while [ $# -gt 0 ]; do
			case "$1" in
				--quiet) ;;
				*) unit="$1" ;;
			esac
			shift
		done
		[ -n "${unit}" ] || exit 3
		svc=$(svc_from_unit "${unit}")
		if service "${svc}" status >/dev/null 2>&1; then
			echo active
			exit 0
		fi
		if "/etc/init.d/${svc}" status >/dev/null 2>&1; then
			echo active
			exit 0
		fi
		if pgrep -x "${svc}" >/dev/null 2>&1; then
			echo active
			exit 0
		fi
		exit 3
		;;
	is-enabled)
		echo enabled
		;;
	status)
		unit="${1:-}"
		svc=$(svc_from_unit "${unit}")
		service "${svc}" status 2>/dev/null || "/etc/init.d/${svc}" status 2>/dev/null || true
		;;
	list-unit-files)
		echo "nginx.service enabled"
		echo "php8.4-fpm.service enabled"
		echo "mariadb.service enabled"
		echo "cron.service enabled"
		;;
	*)
		exit 0
		;;
esac
