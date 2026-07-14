#!/usr/bin/env bash
set -euo pipefail

# setup-wp-nginx.sh
# Installs nginx (official nginx.org repo) + PHP 8.4 (Ondrej PPA) + MariaDB + WordPress + phpMyAdmin with hardening
#
# Supported Environment Variables:
#   DOMAIN            (Required) Domain to install WordPress for (e.g., example.com)
#   USE_WWW           (Optional) Enable www alias? (y/n) [default: y]
#   WP_DB             (Optional) Database name [default: wpdb]
#   WP_DB_USER        (Optional) Database user [default: wpuser]
#   WP_ADMIN_USER     (Optional) WordPress admin username [default: user]
#   LE_EMAIL          (Optional) Admin email [default: admin@$DOMAIN]
#   ENABLE_FAIL2BAN   (Optional) Enable fail2ban? (y/n) [default: y]
#   SKIP_CERTBOT      (Optional) Skip TLS provisioning for CI/test runs (y/n) [default: n]
#   CONT              (Optional) Skip confirmation prompt? (y) [default: y in batch mode]

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

# -------------------------
# Interactive inputs
# -------------------------
echo "-------------------------------------------------------"
log_info "Starting WP + phpMyAdmin + Nginx/PHP 8.4 Setup Wizard"
echo "-------------------------------------------------------"

# Check if any configuration environment variables are set
if [ -n "${DOMAIN:-}" ] || [ -n "${USE_WWW:-}" ] || [ -n "${WP_DB:-}" ] || [ -n "${WP_DB_USER:-}" ] || [ -n "${LE_EMAIL:-}" ] || [ -n "${ENABLE_FAIL2BAN:-}" ]; then
	# Partial or full non-interactive mode
	# DOMAIN is required. If not set, prompt.
	if [ -z "${DOMAIN:-}" ]; then
		read -rp "Domain to install WordPress for (example: example.com): " DOMAIN
	fi

	# Others have defaults or use provided env vars
	USE_WWW=${USE_WWW:-y}
	WP_DB=${WP_DB:-wpdb}
	WP_DB_USER=${WP_DB_USER:-wpuser}
	LE_EMAIL=${LE_EMAIL:-admin@$DOMAIN}
	ENABLE_FAIL2BAN=${ENABLE_FAIL2BAN:-y}

	# Skip confirmation in this mode, assuming user intent
	CONT=${CONT:-y}

	echo
	log_warn "Make sure the DNS A record for $DOMAIN points to this VM's external IP."

else
	# Fully interactive mode
	read -rp "Domain to install WordPress for (example: example.com): " DOMAIN
	read -rp "Enable www.$DOMAIN as alias? (y/n) [y]: " USE_WWW
	USE_WWW=${USE_WWW:-y}
	read -rp "MariaDB WordPress DB name [wpdb]: " WP_DB
	WP_DB=${WP_DB:-wpdb}
	read -rp "MariaDB WordPress DB user [wpuser]: " WP_DB_USER
	WP_DB_USER=${WP_DB_USER:-wpuser}
	read -rp "Admin email for Let's Encrypt & WP notices [admin@$DOMAIN]: " LE_EMAIL
	LE_EMAIL=${LE_EMAIL:-admin@$DOMAIN}
	read -rp "Enable fail2ban (SSH jail) (y/n) [y]: " ENABLE_FAIL2BAN
	ENABLE_FAIL2BAN=${ENABLE_FAIL2BAN:-y}

	echo
	log_warn "Make sure the DNS A record for $DOMAIN points to this VM's external IP."
	read -rp "Continue? (y/n) [y]: " CONT
	CONT=${CONT:-y}
fi

if [[ ! "$CONT" =~ ^[Yy]$ ]]; then
	log_warn "Aborted by user."
	exit 0
fi

# -------------------------
# Input validation
# -------------------------
# These values are interpolated into SQL, file paths, and nginx config below.
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]; then
	log_error "Invalid DOMAIN: '$DOMAIN'. Expected a bare domain name (e.g. example.com)."
	exit 1
fi
if [[ ! "$WP_DB" =~ ^[A-Za-z0-9_]+$ ]]; then
	log_error "Invalid WP_DB: '$WP_DB'. Expected letters, digits, and underscores only."
	exit 1
fi
if [[ ! "$WP_DB_USER" =~ ^[A-Za-z0-9_]+$ ]]; then
	log_error "Invalid WP_DB_USER: '$WP_DB_USER'. Expected letters, digits, and underscores only."
	exit 1
fi

# -------------------------
# Derived & tmp variables
# -------------------------
WWW_DOMAIN=""
if [[ "$USE_WWW" =~ ^[Yy]$ ]]; then WWW_DOMAIN="www.$DOMAIN"; fi
WEB_ROOT="/var/www/$DOMAIN"
NGINX_SITE="/etc/nginx/sites-available/$DOMAIN"
TMPDIR=$(mktemp -d)
CRED_FILE="/root/.wp-credentials"
PMA_ROOT="/usr/share/phpmyadmin"

export DEBIAN_FRONTEND=noninteractive

# -------------------------
# Helper Function for MySQL Execution
# -------------------------
mysql_exec() {
	if mysql -e "$1" >/dev/null 2>&1; then
		return 0
	else
		# Try with password if set. Pass it via MYSQL_PWD rather than -p on the
		# command line so it doesn't briefly appear in `ps` output.
		if [ -n "${MYSQL_ROOT_PASS:-}" ]; then
			MYSQL_PWD="$MYSQL_ROOT_PASS" mysql -u root -e "$1"
		else
			# Failed and no password to try
			return 1
		fi
	fi
}

# -------------------------
# Generate credentials
# -------------------------
log_info "Generating secure passwords..."
WP_ADMIN_USER="${WP_ADMIN_USER:-user}"
# phpMyAdmin expects exactly 32 bytes for the blowfish secret; base64 of 24
# raw bytes yields exactly 32 characters (24/3*4), unlike `rand -base64 32`
# which yields 44.
PMA_BLOWFISH=$(openssl rand -base64 24 | tr -d '\n')

if [ -f "$CRED_FILE" ]; then
	log_info "Found existing credentials file at $CRED_FILE. Using existing credentials."
	# Extract credentials using awk
	MYSQL_ROOT_PASS=$(awk '/MySQL root password:/{getline; print}' "$CRED_FILE")
	WP_DB_PASS=$(awk '/DB password:/{print $3}' "$CRED_FILE")
	WP_ADMIN_PASS=$(awk '/Password:/{if ($1=="Password:") print $2}' "$CRED_FILE")

	if [ -z "$MYSQL_ROOT_PASS" ] || [ -z "$WP_DB_PASS" ] || [ -z "$WP_ADMIN_PASS" ]; then
		log_error "Could not parse one or more credentials from $CRED_FILE."
		log_info "The file may be corrupt or from an unrelated installation. Move it aside and re-run to generate new credentials."
		exit 1
	fi
else
	MYSQL_ROOT_PASS=${MYSQL_ROOT_PASS:-$(openssl rand -base64 18 | tr -d '\n')}
	WP_ADMIN_PASS=${WP_ADMIN_PASS:-$(openssl rand -base64 18 | tr -d '\n')}
	WP_DB_PASS=${WP_DB_PASS:-$(openssl rand -base64 18 | tr -d '\n')}
fi

# -------------------------
# System packages, Ondrej PHP PPA for PHP 8.4, and official Nginx repository
# -------------------------
log_info "Updating system packages and repositories..."
apt-get update -y
apt-get install -y software-properties-common ca-certificates lsb-release apt-transport-https curl gnupg2 wget htop rsync zip unzip python3

log_info "Adding Ondrej PHP PPA for PHP 8.4..."
add-apt-repository -y ppa:ondrej/php

log_info "Adding official Nginx repository..."
if [ ! -f /usr/share/keyrings/nginx-archive-keyring.gpg ]; then
  curl -fsSL https://nginx.org/keys/nginx_signing.key \
    | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" \
  > /etc/apt/sources.list.d/nginx.list
printf 'Package: *\nPin: origin nginx.org\nPin-Priority: 900\n' \
  > /etc/apt/preferences.d/99nginx
apt-get update -y

apt-get install -y nginx mariadb-server \
	php8.4 php8.4-fpm php8.4-cli php8.4-mysql php8.4-curl \
	php8.4-gd php8.4-mbstring php8.4-xml php8.4-zip php8.4-intl php8.4-opcache php8.4-imagick

log_info "Enabling services..."
systemctl enable --now nginx
systemctl enable --now php8.4-fpm

# -------------------------
# PHP-FPM & PHP.ini tuning (FPM pool + opcache + php.ini)
# -------------------------
log_info "Tuning PHP-FPM configuration..."
PHP_FPM_SOCK="/run/php/php8.4-fpm.sock"
if [ ! -S "$PHP_FPM_SOCK" ]; then
	log_error "php8.4-fpm socket not found at $PHP_FPM_SOCK"
	log_info "Check php8.4-fpm status: systemctl status php8.4-fpm"
	exit 1
fi

# Determine CPU cores and set pool sizing
CORES=$(nproc)
RAM_MB=$(free -m | awk '/^Mem:/ {print $2}')

# Cap sizing by available RAM too, not just CPU cores: with memory_limit=256M
# per worker, a core-only formula can size pm.max_children well beyond what
# the box (minus ~768M reserved for MariaDB/OS) can actually hold. Reserve
# ~96M/worker as a realistic average footprint and fold that into the same
# "cores" basis the rest of the formula uses, so the invariant
# min_spare <= start_servers <= max_spare <= max_children is preserved
# automatically regardless of which limit (CPU or RAM) ends up binding.
RAM_CORE_CAP=$(( (RAM_MB - 768) / 480 ))
if [ "$RAM_CORE_CAP" -lt 1 ]; then RAM_CORE_CAP=1; fi
EFFECTIVE_CORES=$CORES
if [ "$RAM_CORE_CAP" -lt "$EFFECTIVE_CORES" ]; then EFFECTIVE_CORES=$RAM_CORE_CAP; fi

# formulas (conservative default): max_children = cores * 5 (min 5), start = cores * 2
MAX_CHILDREN=$((EFFECTIVE_CORES * 5))
if [ "$MAX_CHILDREN" -lt 5 ]; then MAX_CHILDREN=5; fi
START_SERVERS=$((EFFECTIVE_CORES * 2))
if [ "$START_SERVERS" -lt 2 ]; then START_SERVERS=2; fi
MIN_SPARE_SERVERS=$EFFECTIVE_CORES
if [ "$MIN_SPARE_SERVERS" -lt 1 ]; then MIN_SPARE_SERVERS=1; fi
MAX_SPARE_SERVERS=$((EFFECTIVE_CORES * 3))
if [ "$MAX_SPARE_SERVERS" -lt 3 ]; then MAX_SPARE_SERVERS=3; fi
PM_MAX_REQUESTS=500

log_info "Pool Sizing: Cores=$CORES | RAM=${RAM_MB}MB | Max Children=$MAX_CHILDREN"

# Update FPM pool config
FPM_POOL_CONF="/etc/php/8.4/fpm/pool.d/www.conf"
if [ -f "$FPM_POOL_CONF" ]; then
	sed -i "s/^pm = .*/pm = dynamic/" "$FPM_POOL_CONF" || true
	sed -i "s/^pm.max_children = .*/pm.max_children = ${MAX_CHILDREN}/" "$FPM_POOL_CONF" || true
	# If settings not present, append
	grep -q "^pm.max_children" "$FPM_POOL_CONF" || echo "pm.max_children = ${MAX_CHILDREN}" >>"$FPM_POOL_CONF"
	grep -q "^pm.start_servers" "$FPM_POOL_CONF" || echo "pm.start_servers = ${START_SERVERS}" >>"$FPM_POOL_CONF"
	grep -q "^pm.min_spare_servers" "$FPM_POOL_CONF" || echo "pm.min_spare_servers = ${MIN_SPARE_SERVERS}" >>"$FPM_POOL_CONF"
	grep -q "^pm.max_spare_servers" "$FPM_POOL_CONF" || echo "pm.max_spare_servers = ${MAX_SPARE_SERVERS}" >>"$FPM_POOL_CONF"
	grep -q "^pm.max_requests" "$FPM_POOL_CONF" || echo "pm.max_requests = ${PM_MAX_REQUESTS}" >>"$FPM_POOL_CONF"
	# Ensure listen.owner/group match the nginx.org package user (nginx)
	sed -i "s/^listen\.owner = .*/listen.owner = nginx/" "$FPM_POOL_CONF" || true
	sed -i "s/^listen\.group = .*/listen.group = nginx/" "$FPM_POOL_CONF" || true
	grep -q "^listen\.owner" "$FPM_POOL_CONF" || echo "listen.owner = nginx" >>"$FPM_POOL_CONF"
	grep -q "^listen\.group" "$FPM_POOL_CONF" || echo "listen.group = nginx" >>"$FPM_POOL_CONF"
fi

# Tune php.ini (FPM)
PHP_FPM_INI="/etc/php/8.4/fpm/php.ini"
if [ -f "$PHP_FPM_INI" ]; then
	# sensible values for WordPress
	sed -i "s/^memory_limit = .*/memory_limit = 256M/" "$PHP_FPM_INI" || true
	sed -i "s/^upload_max_filesize = .*/upload_max_filesize = 64M/" "$PHP_FPM_INI" || true
	sed -i "s/^post_max_size = .*/post_max_size = 64M/" "$PHP_FPM_INI" || true
	sed -i "s/^max_execution_time = .*/max_execution_time = 300/" "$PHP_FPM_INI" || true
	sed -i -E "s/^;?realpath_cache_size = .*/realpath_cache_size = 4096k/" "$PHP_FPM_INI" || true
	sed -i -E "s/^;?realpath_cache_ttl = .*/realpath_cache_ttl = 600/" "$PHP_FPM_INI" || true
fi

# Configure OPcache for performance
log_info "Configuring OPcache..."
OPCACHE_CONF="/etc/php/8.4/mods-available/opcache.ini"
cat >"$OPCACHE_CONF" <<'OPC'
; Enable OPcache
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.revalidate_freq=2
opcache.validate_timestamps=1
opcache.max_wasted_percentage=5
opcache.save_comments=1
OPC

# Restart PHP-FPM for changes
systemctl restart php8.4-fpm
log_success "PHP 8.4 tuned and restarted."

# -------------------------
# Install phpMyAdmin
# -------------------------
# Re-downloading "latest" on every run is non-idempotent and rotates the
# blowfish secret (killing PMA sessions) for no reason once it's installed.
if [ -f "$PMA_ROOT/index.php" ]; then
	log_info "phpMyAdmin already installed at $PMA_ROOT. Skipping."
else
	log_info "Downloading and Installing phpMyAdmin to $PMA_ROOT ..."

	cd "$TMPDIR"
	wget -q https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.zip -O pma.zip

	PMA_SHA256_EXPECTED=$(curl -fsSL https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.zip.sha256 | awk '{print $1}')
	PMA_SHA256_ACTUAL=$(sha256sum pma.zip | awk '{print $1}')
	if [ "$PMA_SHA256_EXPECTED" != "$PMA_SHA256_ACTUAL" ]; then
		log_error "phpMyAdmin checksum verification failed (expected $PMA_SHA256_EXPECTED, got $PMA_SHA256_ACTUAL)."
		exit 1
	fi

	unzip -q pma.zip
	mv phpMyAdmin-*-all-languages "$PMA_ROOT"

	# Configure PMA
	cp "$PMA_ROOT/config.sample.inc.php" "$PMA_ROOT/config.inc.php"
	# Inject Blowfish Secret
	sed -i "s|\$cfg\['blowfish_secret'\] = '';|\$cfg\['blowfish_secret'\] = '$PMA_BLOWFISH';|" "$PMA_ROOT/config.inc.php"
	# Fix Permissions
	chown -R www-data:www-data "$PMA_ROOT"
	chmod 0755 "$PMA_ROOT"
	# Ensure config is not world writable
	chmod 640 "$PMA_ROOT/config.inc.php"

	# Create a temp directory for PMA to use
	install -d -o www-data -g www-data -m 750 "$PMA_ROOT/tmp"

	log_success "phpMyAdmin installed."
fi

# -------------------------
# nginx site & security headers
# -------------------------
log_info "Configuring Nginx server block for $DOMAIN..."
mkdir -p "$WEB_ROOT"
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 0775 "$WEB_ROOT"

# The official nginx.org package does not create the Ubuntu-style directory
# layout. Create the required directories and configuration hooks.
mkdir -p /etc/nginx/snippets /etc/nginx/sites-available /etc/nginx/sites-enabled

# Add sites-enabled include to nginx.conf if not already present.
if ! grep -q "sites-enabled" /etc/nginx/nginx.conf; then
	sed -i '/include \/etc\/nginx\/conf\.d\/\*\.conf;/a\    include /etc/nginx/sites-enabled/*;' \
		/etc/nginx/nginx.conf
fi

# Create a fastcgi-php.conf shim used by the server block below.
cat >/etc/nginx/snippets/fastcgi-php.conf <<'FCGI'
fastcgi_split_path_info ^(.+?\.php)(/.*)$;
try_files $fastcgi_script_name =404;
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;
fastcgi_index index.php;
include fastcgi_params;
FCGI

SEC_SNIPPET="/etc/nginx/snippets/security-headers.conf"
cat >"$SEC_SNIPPET" <<'NGSEC'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header X-XSS-Protection "1; mode=block" always;
# CSP fix: Added 'blob:' for workers and 'http:' for local dev compatibility
add_header Content-Security-Policy "upgrade-insecure-requests; default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https: http:;" always;
NGSEC

cat >/etc/nginx/snippets/gzip.conf <<'NGGZIP'
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 5;
gzip_min_length 256;
gzip_types text/plain text/css text/xml application/xml application/javascript application/json image/svg+xml;
NGGZIP

# Certbot's task later in this script only requests a certificate once
# (skipped if one already exists), so on re-runs this config must describe
# the HTTPS server block itself rather than relying on certbot having
# patched it in place on a prior run.
CERT_EXISTS="n"
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] && [[ ! "${SKIP_CERTBOT:-n}" =~ ^[Yy]$ ]]; then
	CERT_EXISTS="y"
fi

if [[ "$CERT_EXISTS" =~ ^[Yy]$ ]]; then
	SERVER_HEAD=$(cat <<HEAD
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN${WWW_DOMAIN:+ $WWW_DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root $WEB_ROOT;
        allow all;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $DOMAIN${WWW_DOMAIN:+ $WWW_DOMAIN};

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
HEAD
)
else
	SERVER_HEAD=$(cat <<HEAD
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN${WWW_DOMAIN:+ $WWW_DOMAIN};
HEAD
)
fi

# Create nginx server block. certbot (below) obtains the cert on the first
# run; CERT_EXISTS above makes subsequent runs self-sufficient for HTTPS.
cat >"$NGINX_SITE" <<NGINX
$SERVER_HEAD

    root $WEB_ROOT;
    index index.php index.html index.htm;

    client_max_body_size 64m;

    include /etc/nginx/snippets/security-headers.conf;
    include /etc/nginx/snippets/gzip.conf;

    location ^~ /.well-known/acme-challenge/ {
        root $WEB_ROOT;
        allow all;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    # Deny access to sensitive files
    location ~* /(wp-config.php|readme.html|license.txt|install.php) {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Block xmlrpc
    location = /xmlrpc.php {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Static files
    location ~* \.(?:css|js|jpg|jpeg|gif|png|svg|ico|woff2?|ttf|eot|webp|avif)$ {
        try_files \$uri =404;
        expires max;
        access_log off;
    }

    # PHP via php8.4-fpm socket (MAIN)
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$PHP_FPM_SOCK;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    # ----------------------------------------------------
    # phpMyAdmin Location Block (FIXED)
    # ----------------------------------------------------
    location ^~ /phpmyadmin {
        root /usr/share;
        index index.php index.html index.htm;

        location ~ ^/phpmyadmin/(.+\.php)$ {
            # FIX: Removed 'try_files' here because snippets/fastcgi-php.conf already has it.
            root /usr/share;
            fastcgi_pass unix:$PHP_FPM_SOCK;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include snippets/fastcgi-php.conf;
        }

        location ~* ^/phpmyadmin/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
            root /usr/share;
        }
    }

    # Deny hidden files (ACME challenge above takes precedence via ^~)
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Deny access to any files with a .php extension in the uploads directory
    # Works in sub-directory installs and also in multisite network
    # Keep logging the requests to parse later (or to pass to firewall utilities such as fail2ban)
    location ~* /(?:uploads|files)/.*\.php$ {
        deny all;
    }
}
NGINX

ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/"$DOMAIN"
# Remove default site if present
rm -f /etc/nginx/conf.d/default.conf
if [ -f /etc/nginx/sites-enabled/default ]; then
	rm -f /etc/nginx/sites-enabled/default
fi

nginx -t
systemctl reload nginx
log_success "Nginx configured."

# -------------------------
# Harden MariaDB root account & create WP DB/user
# -------------------------
log_info "Creating Database and User..."

# FIX: Create the WordPress database and user FIRST while we still have passwordless root access.
mysql_exec "CREATE DATABASE IF NOT EXISTS \`${WP_DB}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql_exec "CREATE USER IF NOT EXISTS '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';"
# Ensure the user has the correct password (in case it existed with a different one)
mysql_exec "ALTER USER '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';"
mysql_exec "GRANT ALL PRIVILEGES ON \`${WP_DB}\`.* TO '${WP_DB_USER}'@'localhost';"
mysql_exec "FLUSH PRIVILEGES;"

log_info "Hardening MariaDB Root account and removing test data..."
# Extra: ensure no anonymous users and no test DB
# Note: mysql.user is a view on modern MariaDB, so DELETE FROM it fails;
# DROP USER is the supported way to remove the anonymous account.
mysql_exec "DROP USER IF EXISTS ''@'localhost';" || true
mysql_exec "DROP USER IF EXISTS ''@'$(hostname)';" || true
mysql_exec "DROP DATABASE IF EXISTS test;" || true
mysql_exec "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" || true
mysql_exec "FLUSH PRIVILEGES;" || true

# Set MySQL root password LAST (this cuts off passwordless socket access)
# We only do this if we can still log in without a password
if mysql -e "status" >/dev/null 2>&1; then
	mysql <<SQL || true
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
FLUSH PRIVILEGES;
SQL
else
	log_info "MySQL root password likely already set. Skipping ALTER USER."
fi

log_success "Database configured successfully."

# -------------------------
# Install WP-CLI (Moved up)
# -------------------------
if ! command -v wp >/dev/null 2>&1; then
	log_info "Installing WP-CLI..."
	curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o "$TMPDIR/wp-cli.phar"

	WPCLI_SHA512_EXPECTED=$(curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar.sha512)
	WPCLI_SHA512_ACTUAL=$(sha512sum "$TMPDIR/wp-cli.phar" | awk '{print $1}')
	if [ "$WPCLI_SHA512_EXPECTED" != "$WPCLI_SHA512_ACTUAL" ]; then
		log_error "WP-CLI checksum verification failed."
		exit 1
	fi

	install -m 0755 "$TMPDIR/wp-cli.phar" /usr/local/bin/wp
fi

# -------------------------
# Download WordPress via WP-CLI
# -------------------------
log_info "Downloading WordPress Core via WP-CLI..."
mkdir -p "$WEB_ROOT"
# Ensure permissions so www-data can write
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 0775 "$WEB_ROOT"

# Download Core
if ! sudo -H -u www-data -- wp --path="$WEB_ROOT" core is-installed --allow-root 2>/dev/null; then
    sudo -H -u www-data -- wp --path="$WEB_ROOT" core download --skip-content --force
    # Note: --skip-content avoids overwriting default themes/plugins if re-running
    # --force ensures it downloads even if folder exists
fi

# -------------------------
# Generate wp-config.php via WP-CLI
# -------------------------
WP_CONFIG="$WEB_ROOT/wp-config.php"

if [ ! -f "$WP_CONFIG" ]; then
    log_info "Generating wp-config.php via WP-CLI..."
    sudo -H -u www-data -- wp --path="$WEB_ROOT" config create \
        --dbname="$WP_DB" \
        --dbuser="$WP_DB_USER" \
        --dbpass="$WP_DB_PASS" \
        --locale="en_US" \
        --force
else
    log_info "wp-config.php already exists. Skipping generation."
fi

# -------------------------
# Inject Security/SSL settings
# -------------------------
if ! grep -q "SSL/Reverse Proxy Fix (added by installer)" "$WP_CONFIG"; then
    log_info "Injecting Security Hardening into wp-config.php..."

    # Use sed to insert constants BEFORE the 'require_once' line so they take effect.
    # This avoids the "Strange wp-config.php" error by ensuring wp-settings.php is loaded last.
    sed -i "/require_once ABSPATH . 'wp-settings.php';/i \\
\\
/** SSL/Reverse Proxy Fix (added by installer) */\\
if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {\\
    \$_SERVER['HTTPS'] = 'on';\\
}\\
\\
/** Security & auto-update settings */\\
define('FS_METHOD', 'direct');\\
define('DISALLOW_FILE_EDIT', true);\\
define('WP_AUTO_UPDATE_CORE', 'minor'); // Updated to 'minor' per request\\
if ( ! defined('FORCE_SSL_ADMIN') ) define('FORCE_SSL_ADMIN', true);" "$WP_CONFIG"
else
    log_info "Security Hardening already present in wp-config.php. Skipping."
fi

# -------------------------
# Create MU-plugin for XML-RPC mitigation
# -------------------------
log_info "Creating MU-plugin to disable XML-RPC pingback..."
MU_PLUGINS_DIR="$WEB_ROOT/wp-content/mu-plugins"
mkdir -p "$MU_PLUGINS_DIR"
cat >"$MU_PLUGINS_DIR/disable-xmlrpc-pingback.php" <<'PHP'
<?php
/**
 * Plugin Name: Disable XML-RPC Pingback
 * Description: Disable pingback.ping xmlrpc method to prevent WordPress from participating in DDoS attacks.
 * More info at: https://docs.bitnami.com/general/apps/wordpress/troubleshooting/xmlrpc-and-pingback/
 */

if ( ! defined( 'WP_CLI' ) ) {
    // remove x-pingback HTTP header
    add_filter( "wp_headers", function( $headers ) {
        if ( isset( $headers['X-Pingback'] ) ) {
            unset( $headers['X-Pingback'] );
        }
        return $headers;
    });
    // disable pingbacks
    add_filter( "xmlrpc_methods", function( $methods ) {
        if ( isset( $methods['pingback.ping'] ) ) {
            unset( $methods['pingback.ping'] );
        }
        return $methods;
    });
}
PHP

# Lock wp-config (prevent world-read)
chmod 640 "$WP_CONFIG"

# Remove version files
rm -f "$WEB_ROOT/readme.html" "$WEB_ROOT/license.txt" || true

# -------------------------
# Ownership & Permissions Update
# -------------------------
log_info "Applying permission hardening (www-data:www-data, 0775/0664)..."
chown -R www-data:www-data "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 0775 {} +
find "$WEB_ROOT" -type f -exec chmod 0664 {} +

# -------------------------
# WordPress core install
# -------------------------
# Install WP (non-interactive). Use HTTP initially (Certbot will enable HTTPS).
SITE_URL="http://$DOMAIN"
SITE_TITLE="$DOMAIN"

if ! sudo -H -u www-data -- wp --path="$WEB_ROOT" core is-installed --allow-root 2>/dev/null; then
	log_info "Running WP-CLI Core Install..."
	sudo -H -u www-data -- wp --path="$WEB_ROOT" core install \
		--url="$SITE_URL" \
		--title="$SITE_TITLE" \
		--admin_user="$WP_ADMIN_USER" \
		--admin_password="$WP_ADMIN_PASS" \
		--admin_email="$LE_EMAIL" \
		--skip-email \
		--allow-root
	log_success "WordPress Core Installed."
else
	log_info "WordPress already installed. Skipping core install."
fi

# If 'admin' exists, reassign posts to 'user' and delete admin
if sudo -H -u www-data -- wp --path="$WEB_ROOT" user get admin --field=ID --allow-root >/dev/null 2>&1; then
	log_info "Removing default 'admin' user..."
	sudo -H -u www-data -- wp --path="$WEB_ROOT" user delete admin --reassign="$WP_ADMIN_USER" --allow-root || true
fi

# Ensure 'user' has administrator role
sudo -H -u www-data -- wp --path="$WEB_ROOT" user set-role "$WP_ADMIN_USER" administrator --allow-root || true

# -------------------------
# Default Theme
# -------------------------
# --skip-content above means there are no theme packages on disk at all, so
# a fresh install renders a blank front page. Install a default theme, but
# only if nothing is active yet, so re-runs never stomp an admin's later
# theme choice.
ACTIVE_THEME=$(sudo -H -u www-data -- wp --path="$WEB_ROOT" theme list --status=active --field=name --allow-root 2>/dev/null || true)
if [ -z "$ACTIVE_THEME" ]; then
	log_info "Installing and activating default theme..."
	sudo -H -u www-data -- wp --path="$WEB_ROOT" theme install twentytwentyfive --activate --allow-root || true
fi

# -------------------------
# Install Essential Plugins
# -------------------------
log_info "Installing Essential Plugins..."
sudo -H -u www-data -- wp --path="$WEB_ROOT" plugin install \
	jetpack \
	akismet \
	jetpack-protect \
	jetpack-boost \
	amp \
	sucuri-scanner \
	wordfence \
	wp-mail-smtp \
	cloudflare-flexible-ssl \
	google-analytics-for-wordpress \
	updraftplus \
	better-search-replace \
	--allow-root || true

# Enable plugin/theme auto-updates (after install, so the essential plugins
# above are actually covered instead of --skip-content leaving nothing to enable)
log_info "Enabling Plugin/Theme auto-updates..."
sudo -H -u www-data -- wp --path="$WEB_ROOT" plugin auto-updates enable --all --allow-root || true
sudo -H -u www-data -- wp --path="$WEB_ROOT" theme auto-updates enable --all --allow-root || true

# Create weekly WP update cron (applies updates automatically)
CRON_JOB="/etc/cron.weekly/wp-updates"
cat >"$CRON_JOB" <<'CRON'
#!/usr/bin/env bash
WP_PATH=PLACEHOLDER_DOCROOT
sudo -H -u www-data -- wp --path="$WP_PATH" core update --minor --allow-root || true
sudo -H -u www-data -- wp --path="$WP_PATH" plugin update --all --allow-root || true
sudo -H -u www-data -- wp --path="$WP_PATH" theme update --all --allow-root || true
echo "WP weekly update run for $WP_PATH" | logger -t wp-updates
CRON
sed -i "s|PLACEHOLDER_DOCROOT|$WEB_ROOT|g" "$CRON_JOB"
chmod 750 "$CRON_JOB"
chown root:root "$CRON_JOB"
log_success "Weekly update cron created."

# -------------------------
# Certbot (apt) - obtain TLS and configure nginx
# -------------------------
log_info "Installing Certbot and Python3-Certbot-Nginx via apt..."
if [[ "${SKIP_CERTBOT:-n}" =~ ^[Yy]$ ]]; then
	log_warn "Skipping Certbot because SKIP_CERTBOT is enabled."
else
	apt-get install -y certbot python3-certbot-nginx

	CERT_DOMAINS=("-d" "$DOMAIN")
	if [ -n "$WWW_DOMAIN" ]; then CERT_DOMAINS+=("-d" "$WWW_DOMAIN"); fi

	log_info "Requesting SSL Certificate. If this fails, check your DNS records!"
	certbot --nginx "${CERT_DOMAINS[@]}" --email "$LE_EMAIL" --agree-tos --no-eff-email --redirect --expand --non-interactive || {
		log_error "Certbot reported issues. You may need to run it manually."
	}

	# Ensure certbot renewal service/timer is enabled
	log_info "Enabling Certbot renewal timer..."
	systemctl enable --now certbot.timer

	if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
		log_info "Pointing WordPress site URLs at https://$DOMAIN..."
		sudo -H -u www-data -- wp --path="$WEB_ROOT" option update home "https://$DOMAIN" --allow-root || true
		sudo -H -u www-data -- wp --path="$WEB_ROOT" option update siteurl "https://$DOMAIN" --allow-root || true
	fi
fi

# -------------------------
# Unattended security updates
# -------------------------
log_info "Configuring Unattended Upgrades..."
apt-get install -y unattended-upgrades apt-listchanges

cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'UUCONF'
// Automatically upgrade packages from these (origin:archive) pairs
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    // "${distro_id}:${distro_codename}-updates";
    // "${distro_id}:${distro_codename}-proposed";
    // "${distro_id}:${distro_codename}-backports";
};

// List of packages to not update
Unattended-Upgrade::Package-Blacklist {
};

// Send email to this address for problems or packages upgrades.
// If empty or unset then no email is sent, make sure that you have a
// working mail setup on your system. A package that provides 'mailx' must
// be installed.
Unattended-Upgrade::Mail "PLACEHOLDER_ADMIN_EMAIL";

// Set this value to "true" to get emails only on errors. Default is to
// always send an email if the log has changed.
Unattended-Upgrade::MailOnlyOnError "true";

// Remove unused automatically installed kernel-related packages (kernel
// images, kernel headers and kernel version locked tools).
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Do automatic removal of new unused dependencies after the upgrade
// (equivalent to apt-get autoremove)
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot *WITHOUT CONFIRMATION* if
//  the file /var/run/reboot-required is found after the upgrade
Unattended-Upgrade::Automatic-Reboot "false";
UUCONF
sed -i "s|PLACEHOLDER_ADMIN_EMAIL|$LE_EMAIL|" /etc/apt/apt.conf.d/50unattended-upgrades

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'AUCONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AUCONF

# -------------------------
# Fail2ban (optional)
# -------------------------
if [[ "$ENABLE_FAIL2BAN" =~ ^[Yy] ]]; then
	log_info "Installing and configuring Fail2Ban..."
	apt-get install -y fail2ban
	systemctl enable --now fail2ban
	cat >/etc/fail2ban/jail.local <<'JAIL'
[DEFAULT]
bantime = 1h
findtime = 15m
maxretry = 5
backend = auto

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
JAIL
	systemctl restart fail2ban
	log_success "Fail2Ban active."
fi

# -------------------------
# Final perms & cleanup
# -------------------------
log_info "Finalizing permissions and cleaning up..."

# Ensure ownerships - User Requested: www-data:www-data, 0775 dirs, 0664 files
chown -R www-data:www-data "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 0775 {} +
find "$WEB_ROOT" -type f -exec chmod 0664 {} +

# Re-lock wp-config (prevent world-read)
chmod 640 "$WP_CONFIG" || true
# Note: Owner is already www-data from recursive chown above, so web server can still read it.

rm -rf "$TMPDIR"
systemctl reload php8.4-fpm || true
systemctl reload nginx || true

# -------------------------
# Save credentials to secure file
# -------------------------
{
	echo "----- WordPress & DB Credentials for $DOMAIN -----"
	echo "Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
	echo
	echo "MySQL root password:"
	echo "$MYSQL_ROOT_PASS"
	echo
	echo "WordPress DB:"
	echo "  DB name: $WP_DB"
	echo "  DB user: $WP_DB_USER"
	echo "  DB password: $WP_DB_PASS"
	echo
	echo "WordPress admin (new) account:"
	echo "  Username: $WP_ADMIN_USER"
	echo "  Password: $WP_ADMIN_PASS"
	echo "  Admin email: $LE_EMAIL"
	echo
	echo "phpMyAdmin:"
	echo "  URL: https://$DOMAIN/phpmyadmin"
	echo "  Use the 'WordPress DB' credentials above to login."
	echo "  Note: You cannot login as 'root' via PMA by default."
	echo
	echo "PHP-FPM tuning (www pool):"
	echo "  cpu_cores = $CORES"
	echo "  pm.max_children = $MAX_CHILDREN"
	echo "  pm.start_servers = $START_SERVERS"
	echo "  pm.min_spare_servers = $MIN_SPARE_SERVERS"
	echo "  pm.max_spare_servers = $MAX_SPARE_SERVERS"
	echo "  pm.max_requests = $PM_MAX_REQUESTS"
	echo
	echo "Notes:"
	echo " - Webroot: $WEB_ROOT"
	echo " - WP weekly update cron: $CRON_JOB"
	echo " - Certbot (apt) used to request TLS"
} >"$CRED_FILE"

chmod 600 "$CRED_FILE"
chown root:root "$CRED_FILE"

# -------------------------
# Final output
# -------------------------
echo -e ""
echo -e "=============================================================="
echo -e "${GREEN}WordPress + phpMyAdmin installation complete for: $DOMAIN${NC}"
echo -e ""
echo -e "Credentials saved to: ${YELLOW}$CRED_FILE${NC} (mode 600)"
if [ -t 1 ]; then
	# Only echo plaintext credentials to an interactive terminal - a
	# non-interactive run (CI, automation) would otherwise leak them into logs.
	echo -e "-- Displaying generated credentials (also saved) --"
	echo -e ""
	echo -e "${BLUE}MySQL root password:${NC}"
	echo -e "$MYSQL_ROOT_PASS"
	echo -e ""
	echo -e "${BLUE}WordPress DB:${NC}"
	echo -e "  DB name: $WP_DB"
	echo -e "  DB user: $WP_DB_USER"
	echo -e "  DB password: $WP_DB_PASS"
	echo -e ""
	echo -e "${BLUE}WordPress admin (new) account:${NC}"
	echo -e "  Username: $WP_ADMIN_USER"
	echo -e "  Password: $WP_ADMIN_PASS"
	echo -e "  Admin email: $LE_EMAIL"
	echo -e ""
else
	echo -e "Not displaying credentials in this non-interactive session."
	echo -e ""
fi
echo -e "${BLUE}phpMyAdmin:${NC}"
echo -e "  URL: https://$DOMAIN/phpmyadmin"
echo -e ""
echo -e "Important notes:"
echo -e " - Visit https://$DOMAIN to finish and log in."
echo -e " - Visit https://$DOMAIN/phpmyadmin to manage the database."
echo -e " - Ensure GCP VPC firewall allows ingress TCP 80 and 443 to this VM."
echo -e " - To view credentials again: sudo cat $CRED_FILE"
echo -e ""
echo -e "=============================================================="
