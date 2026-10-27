#!/bin/bash
set -e

if [ "${APP_ENV:-local}" = "public-demo" ]; then
    exec bash /var/www/html/deploy/start-demo.sh
fi

echo "[*] ThreatPulse — Initializing deployment..."

# Compose uses an external MariaDB service. Only start embedded MariaDB when
# the application is configured for a local database (e.g. single-container Render).
if [ "${DB_HOST:-localhost}" = "localhost" ] || [ "${DB_HOST:-localhost}" = "127.0.0.1" ]; then

# ── Ensure MySQL system directories exist with correct permissions ──
echo "[*] Ensuring MySQL system directories exist..."
mkdir -p /var/run/mysqld
mkdir -p /var/lib/mysql
chown -R mysql:mysql /var/run/mysqld
chown -R mysql:mysql /var/lib/mysql
chmod 777 /var/run/mysqld

# Initialize MySQL data directory if empty
if [ ! -d "/var/lib/mysql/mysql" ]; then
    echo "[*] Initializing MySQL data directory..."
    mysql_install_db --user=mysql --datadir=/var/lib/mysql > /dev/null 2>&1
fi

# Start MySQL normally
echo "[*] Starting MariaDB..."
mysqld_safe --user=mysql &

# Wait for MySQL to become available
echo "[*] Waiting for MySQL to start..."
for i in $(seq 1 30); do
    if mysqladmin ping --silent 2>/dev/null; then
        echo "[+] MySQL is ready."
        break
    fi
    if [ $i -eq 30 ]; then
        echo "[-] MySQL failed to start within 30 seconds"
        exit 1
    fi
    sleep 1
done

# Setup database and user (root has no password after mysql_install_db)
echo "[*] Configuring database..."

# Create database
mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME:-cybertech_db};"

# Create user — use GRANT which works on all MariaDB versions
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME:-cybertech_db}.* TO '${DB_USER:-redteam_user}'@'localhost' IDENTIFIED BY '${DB_PASS:-root}';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Import base schema
mysql -u root ${DB_NAME:-cybertech_db} < /var/www/html/database.sql 2>/dev/null || echo "[*] Base schema already exists or partially imported."

# Create additional tables required by the dashboard
mysql -u root ${DB_NAME:-cybertech_db} <<'TABLESQL'
CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(45),
    severity ENUM('CRITICAL','HIGH','WARNING','INFO','LOW') DEFAULT 'INFO',
    category VARCHAR(50) DEFAULT 'Other',
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source_ip (source_ip),
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_category (category)
);

CREATE TABLE IF NOT EXISTS ip_geo (
    ip VARCHAR(45) PRIMARY KEY,
    country_code VARCHAR(5),
    country_name VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10,6),
    longitude DECIMAL(10,6),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
TABLESQL

echo "[+] Database configured successfully."
else
    echo "[*] Using external MariaDB at ${DB_HOST}; skipping embedded database setup."
fi

# ── Initial Data Fetch ───────────────────────────
echo "[*] Running initial threat intelligence fetch..."
cd /var/www/html
php api_fetch.php --scheduled &
FETCH_PID=$!
php feodo_realtime.php --scheduled &

# Don't wait for fetch to finish — let it run in background
echo "[*] Threat fetch running in background (PID: $FETCH_PID)"

# ── Cron Setup ───────────────────────────────────
# Cron does not inherit Docker's runtime DB_* environment. Write a private,
# Bash-escaped copy outside the web root so scheduled fetchers use the same
# database as the web application. The directory and file are www-data-only.
install -d -m 0700 -o www-data -g www-data /run/threatpulse
(
    umask 077
    {
        printf 'export DB_HOST=%q\n' "${DB_HOST:-localhost}"
        printf 'export DB_USER=%q\n' "${DB_USER:-redteam_user}"
        printf 'export DB_PASS=%q\n' "${DB_PASS:-root}"
        printf 'export FEED_COLLECTION_ENABLED=%q\n' "${FEED_COLLECTION_ENABLED:-1}"
        printf 'export DB_NAME=%q\n' "${DB_NAME:-cybertech_db}"
    } > /run/threatpulse/ingestion.env
)
chown www-data:www-data /run/threatpulse/ingestion.env
chmod 0600 /run/threatpulse/ingestion.env
# Cron redirects as www-data, so prepare private writable log files.
touch /var/log/feodo_realtime.log /var/log/threat_fetch.log
chown www-data:www-data /var/log/feodo_realtime.log /var/log/threat_fetch.log
chmod 0640 /var/log/feodo_realtime.log /var/log/threat_fetch.log
echo "[*] Starting cron daemon..."
cron

# ── Apache ───────────────────────────────────────
echo "[+] Starting Apache on port ${PORT:-10000}..."
echo "[+] ThreatPulse SOC Dashboard is LIVE!"

# Start Apache in foreground (keeps container alive)
exec apache2-foreground
