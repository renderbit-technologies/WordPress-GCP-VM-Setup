#!/usr/bin/env bash
set -euo pipefail

# tests/verify-deployment.sh
# Shared post-install verification for both the Bash and Ansible deployment
# paths. Run as root on the target host (VM or CI runner) after provisioning.
#
# Required:
#   DOMAIN              Domain the site was installed for
#
# Optional:
#   WEB_ROOT             Webroot path                        [default: /var/www/$DOMAIN]
#   CRED_FILE             Credentials file path                [default: /root/.wp-credentials]
#   WP_DB / WP_DB_USER / WP_DB_PASS   DB access check (skipped if any unset)
#   CHECK_SWAP            Verify swap is active (y/n)          [default: y]
#   CHECK_UPLOAD_SIZE      Verify >1MB uploads pass nginx (y/n)  [default: y]

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

if [ -z "${DOMAIN:-}" ]; then
	echo "DOMAIN must be set" >&2
	exit 1
fi

WEB_ROOT="${WEB_ROOT:-/var/www/$DOMAIN}"
CRED_FILE="${CRED_FILE:-/root/.wp-credentials}"
CHECK_SWAP="${CHECK_SWAP:-y}"
CHECK_UPLOAD_SIZE="${CHECK_UPLOAD_SIZE:-y}"

status_code() {
	curl -s -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" "http://127.0.0.1$1"
}

body_of() {
	curl -sL --resolve "$DOMAIN:80:127.0.0.1" --resolve "$DOMAIN:443:127.0.0.1" -H "Host: $DOMAIN" "http://127.0.0.1$1"
}

# --- Front page ---
CODE=$(status_code "/")
if [ "$CODE" = "200" ] || [ "$CODE" = "301" ]; then
	pass "Front page returned HTTP $CODE"
else
	fail "Front page returned HTTP $CODE (expected 200 or 301)"
fi

for _ in $(seq 1 15); do
	BODY=$(body_of "/")
	echo "$BODY" | grep -qi "wp-content\|wordpress" && break
	# A reload of php8.4-fpm/nginx can leave the front page briefly blank
	# right after provisioning; give it a moment to settle before failing.
	# A 5x1s budget wasn't always enough on slower/contended CI runners.
	sleep 2
done
if echo "$BODY" | grep -qi "wp-content\|wordpress"; then
	pass "Front page contains WordPress markup"
else
	fail "Front page does not look like WordPress output (blank theme / no active theme?)"
fi

# --- wp-login.php ---
# wp-config.php sets FORCE_SSL_ADMIN, so over plain HTTP (no cert in test
# environments) this legitimately 302-redirects to https instead of a 200.
CODE=$(status_code "/wp-login.php")
if [ "$CODE" = "200" ] || [ "$CODE" = "302" ]; then
	pass "wp-login.php returned HTTP $CODE"
else
	fail "wp-login.php returned HTTP $CODE (expected 200 or 302)"
fi

# --- phpMyAdmin ---
CODE=$(status_code "/phpmyadmin/")
if [ "$CODE" = "200" ]; then
	pass "phpMyAdmin returned HTTP 200"
else
	fail "phpMyAdmin returned HTTP $CODE (expected 200)"
fi

# --- Blocked paths ---
for path in /xmlrpc.php /wp-config.php; do
	CODE=$(status_code "$path")
	if [ "$CODE" = "403" ]; then
		pass "$path correctly blocked (403)"
	else
		fail "$path returned HTTP $CODE (expected 403)"
	fi
done

# --- Hidden files ---
if [ -d "$WEB_ROOT" ]; then
	echo "test" >"$WEB_ROOT/.verify-hidden-test"
	chmod 644 "$WEB_ROOT/.verify-hidden-test"
	CODE=$(status_code "/.verify-hidden-test")
	rm -f "$WEB_ROOT/.verify-hidden-test"
	if [ "$CODE" = "403" ]; then
		pass "Hidden files correctly blocked (403)"
	else
		fail "Hidden file returned HTTP $CODE (expected 403)"
	fi
else
	info "Skipping hidden-file check ($WEB_ROOT does not exist)"
fi

# --- PHP execution in uploads ---
if [ -d "$WEB_ROOT/wp-content" ]; then
	UPLOADS_DIR="$WEB_ROOT/wp-content/uploads"
	mkdir -p "$UPLOADS_DIR"
	echo "<?php echo 'should-not-execute';" >"$UPLOADS_DIR/verify-test.php"
	chmod 644 "$UPLOADS_DIR/verify-test.php"
	CODE=$(status_code "/wp-content/uploads/verify-test.php")
	rm -f "$UPLOADS_DIR/verify-test.php"
	if [ "$CODE" = "403" ]; then
		pass "PHP execution in uploads/ correctly blocked (403)"
	else
		fail "PHP file in uploads/ returned HTTP $CODE (expected 403)"
	fi
else
	info "Skipping uploads PHP-execution check (wp-content not present)"
fi

# --- Upload size limit (client_max_body_size) ---
if [[ "$CHECK_UPLOAD_SIZE" =~ ^[Yy]$ ]]; then
	BIGFILE=$(mktemp)
	dd if=/dev/zero of="$BIGFILE" bs=1M count=2 >/dev/null 2>&1
	CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" --data-binary "@$BIGFILE" "http://127.0.0.1/")
	rm -f "$BIGFILE"
	if [ "$CODE" = "413" ]; then
		fail "A 2MB POST body was rejected with 413 (client_max_body_size too low)"
	else
		pass "A 2MB POST body was accepted at the nginx layer (HTTP $CODE)"
	fi
fi

# --- Swap ---
if [[ "$CHECK_SWAP" =~ ^[Yy]$ ]]; then
	if swapon --show | grep -q "/swapfile"; then
		pass "Swap is active"
	else
		fail "Swap is not active"
	fi
fi

# --- Credentials file ---
if [ -f "$CRED_FILE" ]; then
	MODE=$(stat -c "%a" "$CRED_FILE" 2>/dev/null || stat -f "%Lp" "$CRED_FILE")
	if [ "$MODE" = "600" ]; then
		pass "Credentials file exists with mode 600"
	else
		fail "Credentials file has mode $MODE (expected 600)"
	fi
else
	fail "Credentials file $CRED_FILE not found"
fi

# --- WP-Cron disabled + system cron runner ---
# Checks the actual runtime value via `wp eval`, not just whether the
# constant name appears in the file - a grep for the name would also pass
# on a stray `false` or a comment mentioning it.
if [ -f "$WEB_ROOT/wp-config.php" ]; then
	WP_CRON_VALUE=$(wp --path="$WEB_ROOT" eval "echo defined('DISABLE_WP_CRON') && DISABLE_WP_CRON ? 'true' : 'false';" --allow-root 2>/dev/null || echo "error")
	if [ "$WP_CRON_VALUE" = "true" ]; then
		pass "DISABLE_WP_CRON is set to true in wp-config.php"
	else
		fail "DISABLE_WP_CRON is not set to true in wp-config.php (value: $WP_CRON_VALUE)"
	fi
else
	info "Skipping DISABLE_WP_CRON check ($WEB_ROOT/wp-config.php does not exist)"
fi

if [ -f /etc/cron.d/wp-cron ]; then
	MODE=$(stat -c "%a" /etc/cron.d/wp-cron 2>/dev/null || stat -f "%Lp" /etc/cron.d/wp-cron)
	if [ "$MODE" = "644" ] && grep -q "due-now" /etc/cron.d/wp-cron; then
		pass "/etc/cron.d/wp-cron exists, mode 644, runs --due-now"
	else
		fail "/etc/cron.d/wp-cron exists but mode ($MODE) or content is unexpected"
	fi
else
	fail "/etc/cron.d/wp-cron not found"
fi

# The cron.d file is inert without the daemon actually running - if cron is
# stopped, every scheduled task silently breaks once page-load spawning is
# disabled, with nothing in the filesystem checks above to reveal that.
if systemctl is-active --quiet cron 2>/dev/null; then
	pass "cron daemon is active"
else
	fail "cron daemon is not active"
fi

# --- sucuri-scanner absent from a fresh install ---
# Only informational when found: this script also runs against boxes
# provisioned by an earlier version that did install sucuri-scanner, and an
# existing install isn't removed on upgrade (see the credentials-file
# note), so its presence there is expected, not a bug - don't hard-fail a
# supported rerun/upgrade state.
if [ -d "$WEB_ROOT/wp-content/plugins" ]; then
	if [ ! -d "$WEB_ROOT/wp-content/plugins/sucuri-scanner" ]; then
		pass "sucuri-scanner is not installed"
	else
		info "sucuri-scanner is installed (expected if this box was provisioned before it was dropped from the default plugin list; not auto-removed on upgrade)"
	fi
else
	info "Skipping sucuri-scanner check (wp-content/plugins not present)"
fi

# --- Database access ---
# WP_DB_PASS may be auto-generated (e.g. by the Ansible path) and unknown to
# the caller; fall back to parsing it out of the credentials file.
if [ -z "${WP_DB_PASS:-}" ] && [ -n "${WP_DB:-}" ] && [ -n "${WP_DB_USER:-}" ] && [ -f "$CRED_FILE" ]; then
	WP_DB_PASS=$(awk '/DB password:/{print $3}' "$CRED_FILE")
fi

if [ -n "${WP_DB:-}" ] && [ -n "${WP_DB_USER:-}" ] && [ -n "${WP_DB_PASS:-}" ]; then
	# --no-defaults must come first: this script runs as root, and if root has
	# a ~/.my.cnf (the Ansible path writes one for its own passwordless CLI
	# access), the mysql client's [client] password there silently outranks
	# MYSQL_PWD below - it would then auth as $WP_DB_USER using root's DB
	# password instead, always failing with "Access denied".
	DB_ERROR=$(MYSQL_PWD="$WP_DB_PASS" mysql --no-defaults -u "$WP_DB_USER" -h localhost -e "USE \`$WP_DB\`;" 2>&1 >/dev/null) && DB_OK=1 || DB_OK=0
	if [ "$DB_OK" = "1" ]; then
		pass "Database access verified for $WP_DB_USER@$WP_DB"
	else
		fail "Could not connect to database $WP_DB as $WP_DB_USER: $DB_ERROR"
	fi
else
	info "Skipping database check (WP_DB/WP_DB_USER/WP_DB_PASS not set)"
fi

echo
echo "-------------------------------------------------------"
echo "Verification summary: $PASS passed, $FAIL failed"
echo "-------------------------------------------------------"

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
