#!/bin/bash
set -e

echo "[*] ThreatPulse — Initializing deployment..."

# ── MySQL Setup ──────────────────────────────────
echo "[*] Starting MariaDB..."

# Initialize MySQL data directory if empty
if [ ! -d "/var/lib/mysql/mysql" ]; then
    echo "[*] Initializing MySQL data directory..."
    mysql_install_db --user=mysql --datadir=/var/lib/mysql > /dev/null 2>&1
fi

# Start MySQL normally (NOT with --skip-grant-tables)
mysqld_safe &

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

# ── Initial Data Fetch ───────────────────────────
echo "[*] Running initial threat intelligence fetch..."
cd /var/www/html
php api_fetch.php 2>/dev/null &
FETCH_PID=$!

# Don't wait for fetch to finish — let it run in background
echo "[*] Threat fetch running in background (PID: $FETCH_PID)"

# ── Cron Setup ───────────────────────────────────
echo "[*] Starting cron daemon..."
cron

# ── Apache ───────────────────────────────────────
echo "[+] Starting Apache on port ${PORT:-10000}..."
echo "[+] ThreatPulse SOC Dashboard is LIVE!"

# Start Apache in foreground (keeps container alive)
exec apache2-foreground
