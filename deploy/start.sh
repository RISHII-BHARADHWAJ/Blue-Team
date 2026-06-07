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

# Start MySQL in background
mysqld_safe --skip-grant-tables &
MYSQL_PID=$!

# Wait for MySQL to become available
echo "[*] Waiting for MySQL to start..."
for i in $(seq 1 30); do
    if mysqladmin ping --silent 2>/dev/null; then
        echo "[+] MySQL is ready."
        break
    fi
    sleep 1
done

# Setup database and user
echo "[*] Configuring database..."
mysql -u root <<EOF
-- Create database
CREATE DATABASE IF NOT EXISTS ${DB_NAME:-cybertech_db};

-- Create user and grant privileges
CREATE USER IF NOT EXISTS '${DB_USER:-redteam_user}'@'localhost' IDENTIFIED BY '${DB_PASS:-root}';
GRANT ALL PRIVILEGES ON ${DB_NAME:-cybertech_db}.* TO '${DB_USER:-redteam_user}'@'localhost';
FLUSH PRIVILEGES;

-- Switch to the database
USE ${DB_NAME:-cybertech_db};

-- Create tables (IF NOT EXISTS to be idempotent)
$(cat /var/www/html/database.sql)

-- Create the logs table (required by dashboard)
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

-- Create the ip_geo table (required by dashboard map)
CREATE TABLE IF NOT EXISTS ip_geo (
    ip VARCHAR(45) PRIMARY KEY,
    country_code VARCHAR(5),
    country_name VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10,6),
    longitude DECIMAL(10,6),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF

echo "[+] Database configured successfully."

# Stop the skip-grant-tables instance and restart properly
mysqladmin shutdown 2>/dev/null || true
sleep 2

# Start MySQL properly (with authentication)
mysqld_safe &
sleep 3

# Wait for MySQL to become available again
for i in $(seq 1 15); do
    if mysqladmin ping --silent 2>/dev/null; then
        echo "[+] MySQL restarted with authentication."
        break
    fi
    sleep 1
done

# ── Initial Data Fetch ───────────────────────────
echo "[*] Running initial threat intelligence fetch..."
cd /var/www/html
php api_fetch.php 2>/dev/null || echo "[-] Initial fetch had issues (non-fatal)"

# ── Cron Setup ───────────────────────────────────
echo "[*] Starting cron daemon..."
cron

# ── Apache ───────────────────────────────────────
echo "[+] Starting Apache on port ${PORT:-10000}..."
echo "[+] ThreatPulse SOC Dashboard is LIVE!"

# Start Apache in foreground
exec apache2-foreground
