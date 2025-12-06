#!/usr/bin/env bash
set -euo pipefail

# setup-wp-nginx.sh
# Installs nginx + PHP 8.3 (Ondrej PPA) + MariaDB + WordPress + phpMyAdmin with hardening
#
# Supported Environment Variables:
#   DOMAIN            (Required) Domain to install WordPress for (e.g., example.com)
#   USE_WWW           (Optional) Enable www alias? (y/n) [default: y]
#   WP_DB             (Optional) Database name [default: wpdb]
#   WP_DB_USER        (Optional) Database user [default: wpuser]
#   LE_EMAIL          (Optional) Admin email [default: admin@$DOMAIN]
#   ENABLE_FAIL2BAN   (Optional) Enable fail2ban? (y/n) [default: y]
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
log_info "Starting WP + phpMyAdmin + Nginx/PHP 8.3 Setup Wizard"
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
# Derived & tmp variables
# -------------------------
WWW_DOMAIN=""
if [[ "$USE_WWW" =~ ^[Yy]$ ]]; then WWW_DOMAIN="www.$DOMAIN"; fi
WEB_ROOT="/var/www/$DOMAIN"
NGINX_SITE="/etc/nginx/sites-available/$DOMAIN"
TMPDIR=$(mktemp -d)
CRED_FILE="$HOME/.wp-credentials"
PMA_ROOT="/usr/share/phpmyadmin"

export DEBIAN_FRONTEND=noninteractive

# -------------------------
# Helper Function for MySQL Execution
# -------------------------
mysql_exec() {
	if mysql -e "$1" >/dev/null 2>&1; then
		return 0
	else
		# Try with password if set
		if [ -n "${MYSQL_ROOT_PASS:-}" ]; then
			mysql -u root -p"$MYSQL_ROOT_PASS" -e "$1"
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
WP_ADMIN_USER="user"
PMA_BLOWFISH=$(openssl rand -base64 32 | tr -d '\n')

if [ -f "$CRED_FILE" ]; then
	log_info "Found existing credentials file at $CRED_FILE. Using existing credentials."
	# Extract credentials using awk
	MYSQL_ROOT_PASS=$(awk '/MySQL root password:/{getline; print}' "$CRED_FILE")
	WP_DB_PASS=$(awk '/DB password:/{print $3}' "$CRED_FILE")
	WP_ADMIN_PASS=$(awk '/Password:/{if ($1=="Password:") print $2}' "$CRED_FILE")
else
	MYSQL_ROOT_PASS=$(openssl rand -base64 18 | tr -d '\n')
	WP_ADMIN_PASS=$(openssl rand -base64 18 | tr -d '\n')
	WP_DB_PASS=$(openssl rand -base64 18 | tr -d '\n')
fi

# -------------------------
# System packages & Ondrej PHP PPA for PHP 8.3
# -------------------------
log_info "Updating system packages and repositories..."
apt-get update -y
apt-get install -y software-properties-common ca-certificates lsb-release apt-transport-https curl gnupg2 wget htop rsync zip unzip python3

log_info "Adding Ondrej PPA and installing PHP 8.3 + Extensions..."
add-apt-repository -y ppa:ondrej/php
add-apt-repository -y ppa:ondrej/nginx
apt-get update -y

apt-get install -y nginx mariadb-server \
	php8.3 php8.3-fpm php8.3-cli php8.3-mysql php8.3-curl \
	php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip php8.3-intl php8.3-opcache php8.3-imagick

log_info "Enabling services..."
systemctl enable --now nginx
systemctl enable --now php8.3-fpm

# -------------------------
# PHP-FPM & PHP.ini tuning (FPM pool + opcache + php.ini)
# -------------------------
log_info "Tuning PHP-FPM configuration..."
PHP_FPM_SOCK="/run/php/php8.3-fpm.sock"
if [ ! -S "$PHP_FPM_SOCK" ]; then
	log_error "php8.3-fpm socket not found at $PHP_FPM_SOCK"
	log_info "Check php8.3-fpm status: systemctl status php8.3-fpm"
	exit 1
fi

# Determine CPU cores and set pool sizing
CORES=$(nproc)
# formulas (conservative default): max_children = cores * 5 (min 5), start = cores * 2
MAX_CHILDREN=$((CORES * 5))
if [ "$MAX_CHILDREN" -lt 5 ]; then MAX_CHILDREN=5; fi
START_SERVERS=$((CORES * 2))
if [ "$START_SERVERS" -lt 2 ]; then START_SERVERS=2; fi
MIN_SPARE_SERVERS=$CORES
MAX_SPARE_SERVERS=$((CORES * 3))
PM_MAX_REQUESTS=500

log_info "Pool Sizing: Cores=$CORES | Max Children=$MAX_CHILDREN"

# Update FPM pool config
FPM_POOL_CONF="/etc/php/8.3/fpm/pool.d/www.conf"
if [ -f "$FPM_POOL_CONF" ]; then
	sed -i "s/^pm = .*/pm = dynamic/" "$FPM_POOL_CONF" || true
	sed -i "s/^pm.max_children = .*/pm.max_children = ${MAX_CHILDREN}/" "$FPM_POOL_CONF" || true
	# If settings not present, append
	grep -q "^pm.max_children" "$FPM_POOL_CONF" || echo "pm.max_children = ${MAX_CHILDREN}" >>"$FPM_POOL_CONF"
	grep -q "^pm.start_servers" "$FPM_POOL_CONF" || echo "pm.start_servers = ${START_SERVERS}" >>"$FPM_POOL_CONF"
	grep -q "^pm.min_spare_servers" "$FPM_POOL_CONF" || echo "pm.min_spare_servers = ${MIN_SPARE_SERVERS}" >>"$FPM_POOL_CONF"
	grep -q "^pm.max_spare_servers" "$FPM_POOL_CONF" || echo "pm.max_spare_servers = ${MAX_SPARE_SERVERS}" >>"$FPM_POOL_CONF"
	grep -q "^pm.max_requests" "$FPM_POOL_CONF" || echo "pm.max_requests = ${PM_MAX_REQUESTS}" >>"$FPM_POOL_CONF"
	# Ensure listen.owner/group are www-data
	sed -i "s/^listen.owner = .*/listen.owner = www-data/" "$FPM_POOL_CONF" || true
	sed -i "s/^listen.group = .*/listen.group = www-data/" "$FPM_POOL_CONF" || true
fi

# Tune php.ini (FPM)
PHP_FPM_INI="/etc/php/8.3/fpm/php.ini"
if [ -f "$PHP_FPM_INI" ]; then
	# sensible values for WordPress
	sed -i "s/^memory_limit = .*/memory_limit = 256M/" "$PHP_FPM_INI" || true
	sed -i "s/^upload_max_filesize = .*/upload_max_filesize = 64M/" "$PHP_FPM_INI" || true
	sed -i "s/^post_max_size = .*/post_max_size = 64M/" "$PHP_FPM_INI" || true
	sed -i "s/^max_execution_time = .*/max_execution_time = 300/" "$PHP_FPM_INI" || true
	sed -i "s/^;?realpath_cache_size = .*/realpath_cache_size = 4096k/" "$PHP_FPM_INI" || true
	sed -i "s/^;?realpath_cache_ttl = .*/realpath_cache_ttl = 600/" "$PHP_FPM_INI" || true
fi

# Configure OPcache for performance
log_info "Configuring OPcache..."
OPCACHE_CONF="/etc/php/8.3/mods-available/opcache.ini"
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
opcache.fast_shutdown=1
OPC

# Restart PHP-FPM for changes
systemctl restart php8.3-fpm
log_success "PHP 8.3 tuned and restarted."

# -------------------------
# Install phpMyAdmin
# -------------------------
log_info "Downloading and Installing phpMyAdmin to $PMA_ROOT ..."

# Check if exists, remove to update/reinstall
if [ -d "$PMA_ROOT" ]; then rm -rf "$PMA_ROOT"; fi

cd "$TMPDIR"
wget -q https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.zip -O pma.zip
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
mkdir -p "$PMA_ROOT/tmp"
chmod 777 "$PMA_ROOT/tmp"

log_success "phpMyAdmin installed."

# -------------------------
# nginx site & security headers
# -------------------------
log_info "Configuring Nginx server block for $DOMAIN..."
mkdir -p "$WEB_ROOT"
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 0775 "$WEB_ROOT"

SEC_SNIPPET="/etc/nginx/snippets/security-headers.conf"
cat >"$SEC_SNIPPET" <<'NGSEC'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header X-XSS-Protection "1; mode=block" always;
# CSP fix: Added 'blob:' for workers and 'http:' for local dev compatibility
add_header Content-Security-Policy "upgrade-insecure-requests; default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https: http:;" always;
NGSEC

# Create nginx server block (HTTP). certbot will handle HTTPS redirect.
cat >"$NGINX_SITE" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN${WWW_DOMAIN:+ $WWW_DOMAIN};

    root $WEB_ROOT;
    index index.php index.html index.htm;

    include /etc/nginx/snippets/security-headers.conf;

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
    location ~* \.(?:css|js|jpg|jpeg|gif|png|svg|ico|woff2?|ttf|eot)$ {
        try_files \$uri =404;
        expires max;
        access_log off;
    }

    # PHP via php8.3-fpm socket (MAIN)
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$PHP_FPM_SOCK;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
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
            include fastcgi_params;
            include snippets/fastcgi-php.conf;
        }

        location ~* ^/phpmyadmin/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
            root /usr/share;
        }
    }

    # Deny hidden files
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

ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/$DOMAIN
# Remove default site if present
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
mysql_exec "DELETE FROM mysql.user WHERE User='';" || true
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
	curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
	chmod +x /usr/local/bin/wp
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
if ! sudo -u www-data -- wp --path="$WEB_ROOT" core is-installed --allow-root 2>/dev/null; then
    sudo -u www-data -- wp --path="$WEB_ROOT" core download --skip-content --force || true
    # Note: --skip-content avoids overwriting default themes/plugins if re-running
    # --force ensures it downloads even if folder exists
fi

# -------------------------
# Generate wp-config.php via WP-CLI
# -------------------------
WP_CONFIG="$WEB_ROOT/wp-config.php"

if [ ! -f "$WP_CONFIG" ]; then
    log_info "Generating wp-config.php via WP-CLI..."
    sudo -u www-data -- wp --path="$WEB_ROOT" config create \
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
define('DISALLOW_FILE_EDIT', true);\\
define('WP_AUTO_UPDATE_CORE', 'minor'); // Updated to 'minor' per request\\
if ( ! defined('FORCE_SSL_ADMIN') ) define('FORCE_SSL_ADMIN', true);" "$WP_CONFIG"

# Lock wp-config (prevent world-read)
chmod 640 "$WP_CONFIG"

# Remove version files
rm -f "$WEB_ROOT/readme.html" "$WEB_ROOT/license.txt" || true

# -------------------------
# Ownership & Permissions Update
# -------------------------
log_info "Applying permission hardening (www-data:www-data, 0775/0664)..."
chown -R www-data:www-data "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 0775 {} \;
find "$WEB_ROOT" -type f -exec chmod 0664 {} \;

# -------------------------
# WordPress core install
# -------------------------
# Install WP (non-interactive). Use HTTP initially (Certbot will enable HTTPS).
SITE_URL="http://$DOMAIN"
SITE_TITLE="$DOMAIN"

if ! sudo -u www-data -- wp --path="$WEB_ROOT" core is-installed --allow-root 2>/dev/null; then
	log_info "Running WP-CLI Core Install..."
	sudo -u www-data -- wp --path="$WEB_ROOT" core install \
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
if sudo -u www-data -- wp --path="$WEB_ROOT" user get admin --field=ID --allow-root >/dev/null 2>&1; then
	log_info "Removing default 'admin' user..."
	sudo -u www-data -- wp --path="$WEB_ROOT" user delete admin --reassign="$WP_ADMIN_USER" --allow-root || true
fi

# Ensure 'user' has administrator role
sudo -u www-data -- wp --path="$WEB_ROOT" user set-role "$WP_ADMIN_USER" administrator --allow-root || true

# Enable plugin/theme auto-updates
log_info "Enabling Plugin/Theme auto-updates..."
sudo -u www-data -- wp --path="$WEB_ROOT" plugin auto-updates enable --all --allow-root || true
sudo -u www-data -- wp --path="$WEB_ROOT" theme auto-updates enable --all --allow-root || true

# -------------------------
# Install Essential Plugins
# -------------------------
log_info "Installing Essential Plugins..."
sudo -u www-data -- wp --path="$WEB_ROOT" plugin install \
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

# Create weekly WP update cron (applies updates automatically)
CRON_JOB="/etc/cron.weekly/wp-updates"
cat >"$CRON_JOB" <<'CRON'
#!/usr/bin/env bash
WP_PATH=PLACEHOLDER_DOCROOT
sudo -u www-data -- wp --path="$WP_PATH" core update --minor --allow-root || true
sudo -u www-data -- wp --path="$WP_PATH" plugin update --all --allow-root || true
sudo -u www-data -- wp --path="$WP_PATH" theme update --all --allow-root || true
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

# -------------------------
# Unattended security updates
# -------------------------
log_info "Configuring Unattended Upgrades..."
apt-get install -y unattended-upgrades apt-listchanges
dpkg-reconfigure -f noninteractive unattended-upgrades || true

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
find "$WEB_ROOT" -type d -exec chmod 0775 {} \;
find "$WEB_ROOT" -type f -exec chmod 0664 {} \;

# Re-lock wp-config (prevent world-read)
chmod 640 "$WP_CONFIG" || true
# Note: Owner is already www-data from recursive chown above, so web server can still read it.

rm -rf "$TMPDIR"
systemctl reload php8.3-fpm || true
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
