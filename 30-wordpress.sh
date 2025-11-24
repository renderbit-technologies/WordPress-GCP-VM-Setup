#!/usr/bin/env bash
set -euo pipefail

# setup-wp-nginx-php8.3-prod.sh
# Installs nginx + PHP 8.3 (Ondrej PPA) + MariaDB + WordPress with hardening and tuning
# Run as root on Ubuntu/Debian: sudo bash setup-wp-nginx-php8.3-prod.sh

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

# -------------------------
# Interactive inputs
# -------------------------
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
echo "Make sure the DNS A record for $DOMAIN points to this VM's external IP before continuing."
read -rp "Continue? (y/n) [y]: " CONT
CONT=${CONT:-y}
if [[ ! "$CONT" =~ ^[Yy]$ ]]; then
  echo "Aborted."
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

export DEBIAN_FRONTEND=noninteractive

# -------------------------
# Generate credentials
# -------------------------
MYSQL_ROOT_PASS=$(openssl rand -base64 18 | tr -d '\n' )
WP_ADMIN_USER="user"
WP_ADMIN_PASS=$(openssl rand -base64 18 | tr -d '\n' )
WP_DB_PASS=$(openssl rand -base64 18 | tr -d '\n' )

# -------------------------
# System packages & Ondrej PHP PPA for PHP 8.3
# -------------------------
apt-get update -y
apt-get install -y software-properties-common ca-certificates lsb-release apt-transport-https curl gnupg2

# Add Ondrej PPA and install PHP 8.3 + extensions
add-apt-repository -y ppa:ondrej/php
apt-get update -y

apt-get install -y nginx mariadb-server \
  php8.3 php8.3-fpm php8.3-cli php8.3-mysql php8.3-curl \
  php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip php8.3-intl php8.3-opcache php8.3-imagick

# Enable & start services
systemctl enable --now nginx
systemctl enable --now php8.3-fpm

# -------------------------
# PHP-FPM & PHP.ini tuning (FPM pool + opcache + php.ini)
# -------------------------
PHP_FPM_SOCK="/run/php/php8.3-fpm.sock"
if [ ! -S "$PHP_FPM_SOCK" ]; then
  echo "ERROR: php8.3-fpm socket not found at $PHP_FPM_SOCK"
  echo "Check php8.3-fpm status: systemctl status php8.3-fpm"
  exit 1
fi

# Determine CPU cores and set pool sizing (sensible defaults; tune for your machine)
CORES=$(nproc)
# formulas (conservative default): max_children = cores * 5 (min 5), start = cores * 2
MAX_CHILDREN=$(( CORES * 5 ))
if [ "$MAX_CHILDREN" -lt 5 ]; then MAX_CHILDREN=5; fi
START_SERVERS=$(( CORES * 2 ))
if [ "$START_SERVERS" -lt 2 ]; then START_SERVERS=2; fi
MIN_SPARE_SERVERS=$CORES
MAX_SPARE_SERVERS=$(( CORES * 3 ))
PM_MAX_REQUESTS=500

# Update FPM pool config
FPM_POOL_CONF="/etc/php/8.3/fpm/pool.d/www.conf"
if [ -f "$FPM_POOL_CONF" ]; then
  sed -i "s/^pm = .*/pm = dynamic/" "$FPM_POOL_CONF" || true
  sed -i "s/^pm.max_children = .*/pm.max_children = ${MAX_CHILDREN}/" "$FPM_POOL_CONF" || true
  # If settings not present, append
  grep -q "^pm.max_children" "$FPM_POOL_CONF" || echo "pm.max_children = ${MAX_CHILDREN}" >> "$FPM_POOL_CONF"
  grep -q "^pm.start_servers" "$FPM_POOL_CONF" || echo "pm.start_servers = ${START_SERVERS}" >> "$FPM_POOL_CONF"
  grep -q "^pm.min_spare_servers" "$FPM_POOL_CONF" || echo "pm.min_spare_servers = ${MIN_SPARE_SERVERS}" >> "$FPM_POOL_CONF"
  grep -q "^pm.max_spare_servers" "$FPM_POOL_CONF" || echo "pm.max_spare_servers = ${MAX_SPARE_SERVERS}" >> "$FPM_POOL_CONF"
  grep -q "^pm.max_requests" "$FPM_POOL_CONF" || echo "pm.max_requests = ${PM_MAX_REQUESTS}" >> "$FPM_POOL_CONF"
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
OPCACHE_CONF="/etc/php/8.3/mods-available/opcache.ini"
cat > "$OPCACHE_CONF" <<'OPC'
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

# -------------------------
# nginx site & security headers
# -------------------------
mkdir -p "$WEB_ROOT"
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

SEC_SNIPPET="/etc/nginx/snippets/security-headers.conf"
cat > "$SEC_SNIPPET" <<'NGSEC'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self' 'unsafe-inline' data: https:;" always;
NGSEC

# Create nginx server block (HTTP). certbot will handle HTTPS redirect.
cat > "$NGINX_SITE" <<NGINX
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

    # PHP via php8.3-fpm socket
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$PHP_FPM_SOCK;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    # Deny hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
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

# -------------------------
# Harden MariaDB root account & create WP DB/user
# -------------------------

# FIX: Create the WordPress database and user FIRST while we still have passwordless root access.
mysql -e "CREATE DATABASE IF NOT EXISTS \`${WP_DB}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -e "CREATE USER IF NOT EXISTS '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';"
mysql -e "GRANT ALL PRIVILEGES ON \`${WP_DB}\`.* TO '${WP_DB_USER}'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# Extra: ensure no anonymous users and no test DB
mysql -e "DELETE FROM mysql.user WHERE User='';" || true
mysql -e "DROP DATABASE IF EXISTS test;" || true
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" || true
mysql -e "FLUSH PRIVILEGES;" || true

# Set MySQL root password LAST (this cuts off passwordless socket access)
mysql <<SQL || true
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
FLUSH PRIVILEGES;
SQL

# -------------------------
# Download WordPress and set permissions
# -------------------------
cd "$TMPDIR"
wget -q https://wordpress.org/latest.zip -O latest.zip
unzip -q latest.zip
rsync -a wordpress/ "$WEB_ROOT/"

# Ownership & baseline perms
chown -R root:www-data "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 755 {} \;
find "$WEB_ROOT" -type f -exec chmod 640 {} \;

# wp-content writable by www-data
chown -R www-data:www-data "$WEB_ROOT/wp-content"
find "$WEB_ROOT/wp-content" -type d -exec chmod 775 {} \;
find "$WEB_ROOT/wp-content" -type f -exec chmod 664 {} \;

# -------------------------
# wp-config and salts, hardening constants
# -------------------------
WP_CONFIG="$WEB_ROOT/wp-config.php"
cp "$WEB_ROOT/wp-config-sample.php" "$WP_CONFIG"

perl -i -0777 -pe "s/database_name_here/$WP_DB/s; s/username_here/$WP_DB_USER/s; s/password_here/$WP_DB_PASS/s;" "$WP_CONFIG"

SALT=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
if [ -n "$SALT" ]; then
  if ! perl -i -0777 -pe "s/define\('AUTH_KEY'.+?SECURE_AUTH_SALT'.+?\);/$SALT/s" "$WP_CONFIG"; then
    printf "\n# WP salts\n%s\n" "$SALT" >> "$WP_CONFIG"
  fi
fi

cat >> "$WP_CONFIG" <<'WPSEC'
/** Security & auto-update settings (added by installer) */
define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', true);
if ( ! defined('FORCE_SSL_ADMIN') ) define('FORCE_SSL_ADMIN', true);
WPSEC

# Lock wp-config
chown root:www-data "$WP_CONFIG"
chmod 640 "$WP_CONFIG"

# Remove version files
rm -f "$WEB_ROOT/readme.html" "$WEB_ROOT/license.txt" || true

# -------------------------
# WP-CLI install + WordPress core install
# -------------------------
if ! command -v wp >/dev/null 2>&1; then
  curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
  chmod +x /usr/local/bin/wp
fi

# Install WP (non-interactive). Use HTTP initially (Certbot will enable HTTPS).
SITE_URL="http://$DOMAIN"
SITE_TITLE="$DOMAIN"

if ! sudo -u www-data -- wp --path="$WEB_ROOT" core is-installed --allow-root 2>/dev/null; then
  sudo -u www-data -- wp --path="$WEB_ROOT" core install \
    --url="$SITE_URL" \
    --title="$SITE_TITLE" \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASS" \
    --admin_email="$LE_EMAIL" \
    --skip-email \
    --allow-root
fi

# If 'admin' exists, reassign posts to 'user' and delete admin
if sudo -u www-data -- wp --path="$WEB_ROOT" user get admin --field=ID --allow-root >/dev/null 2>&1; then
  sudo -u www-data -- wp --path="$WEB_ROOT" user delete admin --reassign="$WP_ADMIN_USER" --allow-root || true
fi

# Ensure 'user' has administrator role
sudo -u www-data -- wp --path="$WEB_ROOT" user set-role "$WP_ADMIN_USER" administrator --allow-root || true

# Enable plugin/theme auto-updates
sudo -u www-data -- wp --path="$WEB_ROOT" plugin auto-updates enable --all --allow-root || true
sudo -u www-data -- wp --path="$WEB_ROOT" theme auto-updates enable --all --allow-root || true

# Create weekly WP update cron (applies updates automatically)
CRON_JOB="/etc/cron.weekly/wp-updates"
cat > "$CRON_JOB" <<'CRON'
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

# -------------------------
# Certbot (snap) - obtain TLS and configure nginx
# -------------------------
if ! command -v snap >/dev/null 2>&1; then
  apt-get install -y snapd
  systemctl enable --now snapd.socket
  sleep 3
fi
snap install core || true
snap refresh core || true
if ! snap list certbot >/dev/null 2>&1; then
  snap install --classic certbot
fi
ln -sf /snap/bin/certbot /usr/bin/certbot

CERT_DOMAINS=("-d" "$DOMAIN")
if [ -n "$WWW_DOMAIN" ]; then CERT_DOMAINS+=("-d" "$WWW_DOMAIN"); fi

certbot --nginx "${CERT_DOMAINS[@]}" --email "$LE_EMAIL" --agree-tos --no-eff-email --redirect --expand --non-interactive || {
  echo "Certbot reported issues (it may require manual intervention). Re-run certbot if needed."
}

# Ensure certbot renewal service is enabled
systemctl enable --now snap.certbot.renew.service || true

# -------------------------
# Unattended security updates
# -------------------------
apt-get install -y unattended-upgrades apt-listchanges
dpkg-reconfigure -f noninteractive unattended-upgrades || true

# -------------------------
# Fail2ban (optional)
# -------------------------
if [[ "$ENABLE_FAIL2BAN" =~ ^[Yy] ]]; then
  apt-get install -y fail2ban
  systemctl enable --now fail2ban
  cat > /etc/fail2ban/jail.local <<'JAIL'
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
fi

# -------------------------
# Final perms & cleanup
# -------------------------
# Ensure wp-config locked
chmod 640 "$WP_CONFIG" || true
chown root:www-data "$WP_CONFIG" || true

# Ensure ownerships
chown -R root:www-data "$WEB_ROOT"
chown -R www-data:www-data "$WEB_ROOT/wp-content"
find "$WEB_ROOT" -type d -exec chmod 755 {} \;
find "$WEB_ROOT" -type f -exec chmod 640 {} \;
find "$WEB_ROOT/wp-content" -type d -exec chmod 775 {} \;
find "$WEB_ROOT/wp-content" -type f -exec chmod 664 {} \;

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
  echo " - Certbot (snap) used to request TLS"
} > "$CRED_FILE"

chmod 600 "$CRED_FILE"
chown root:root "$CRED_FILE"

# -------------------------
# Final output
# -------------------------
cat <<EOF

==============================================================
WordPress installation complete for: $DOMAIN

Credentials saved to: $CRED_FILE (mode 600)
-- Displaying generated credentials (also saved) --

MySQL root password:
$MYSQL_ROOT_PASS

WordPress DB:
  DB name: $WP_DB
  DB user: $WP_DB_USER
  DB password: $WP_DB_PASS

WordPress admin (new) account:
  Username: $WP_ADMIN_USER
  Password: $WP_ADMIN_PASS
  Admin email: $LE_EMAIL

PHP-FPM tuning (www pool):
  cpu_cores = $CORES
  pm.max_children = $MAX_CHILDREN
  pm.start_servers = $START_SERVERS
  pm.min_spare_servers = $MIN_SPARE_SERVERS
  pm.max_spare_servers = $MAX_SPARE_SERVERS
  pm.max_requests = $PM_MAX_REQUESTS

Important notes:
 - Visit https://$DOMAIN to finish and log in. FORCE_SSL_ADMIN is enabled.
 - Ensure GCP VPC firewall allows ingress TCP 80 and 443 to this VM.
 - If certbot failed, re-run:
     sudo certbot --nginx -d $DOMAIN ${WWW_DOMAIN:+-d $WWW_DOMAIN} -m $LE_EMAIL --agree-tos --redirect --expand
 - Review PHP-FPM pool values for your instance class. Larger sites may need higher pm.max_children and more memory.
 - For stricter security consider WAF (Cloud Armor or modsecurity), CDN, and backups.

To view credentials:
  sudo cat $CRED_FILE

To manually run WP updates:
  sudo -u www-data -- wp --path="$WEB_ROOT" core update --allow-root
  sudo -u www-data -- wp --path="$WEB_ROOT" plugin update --all --allow-root
  sudo -u www-data -- wp --path="$WEB_ROOT" theme update --all --allow-root

==============================================================
EOF