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
	curl -sL -H "Host: $DOMAIN" "http://127.0.0.1$1"
}

# --- Front page ---
CODE=$(status_code "/")
if [ "$CODE" = "200" ] || [ "$CODE" = "301" ]; then
	pass "Front page returned HTTP $CODE"
else
	fail "Front page returned HTTP $CODE (expected 200 or 301)"
fi

BODY=$(body_of "/")
if echo "$BODY" | grep -qi "wp-content\|wordpress"; then
	pass "Front page contains WordPress markup"
else
	fail "Front page does not look like WordPress output (blank theme / no active theme?)"
fi

# --- wp-login.php ---
CODE=$(status_code "/wp-login.php")
if [ "$CODE" = "200" ]; then
	pass "wp-login.php returned HTTP 200"
else
	fail "wp-login.php returned HTTP $CODE (expected 200)"
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

# --- Database access ---
# WP_DB_PASS may be auto-generated (e.g. by the Ansible path) and unknown to
# the caller; fall back to parsing it out of the credentials file.
if [ -z "${WP_DB_PASS:-}" ] && [ -n "${WP_DB:-}" ] && [ -n "${WP_DB_USER:-}" ] && [ -f "$CRED_FILE" ]; then
	WP_DB_PASS=$(awk '/DB password:/{print $3}' "$CRED_FILE")
fi

if [ -n "${WP_DB:-}" ] && [ -n "${WP_DB_USER:-}" ] && [ -n "${WP_DB_PASS:-}" ]; then
	if MYSQL_PWD="$WP_DB_PASS" mysql -u "$WP_DB_USER" -h localhost -e "USE \`$WP_DB\`;" 2>/dev/null; then
		pass "Database access verified for $WP_DB_USER@$WP_DB"
	else
		fail "Could not connect to database $WP_DB as $WP_DB_USER"
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
