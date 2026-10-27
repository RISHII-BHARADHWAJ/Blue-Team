#!/bin/bash
# Public, disposable demo only. Never connects to the user's Compose database.
set -euo pipefail
cd /var/www/html
export DB_HOST=localhost DB_NAME=threatpulse_public_demo DB_USER=demo_app
export SESSION_COOKIE_SECURE=1 FEED_COLLECTION_ENABLED=0
printf 'pdo_mysql.default_socket=/run/mysqld/mysqld.sock\nmysqli.default_socket=/run/mysqld/mysqld.sock\n' > /usr/local/etc/php/conf.d/demo-database.ini
php deploy/public-demo-accounts.php --preflight
install -d -m 0755 -o mysql -g mysql /run/mysqld
if [ ! -d /var/lib/mysql/mysql ]; then
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null
fi
chown -R mysql:mysql /var/lib/mysql
mariadbd --user=mysql --skip-networking --innodb-buffer-pool-size=64M --max-connections=15 &
for attempt in $(seq 1 60); do
    if mariadb-admin --protocol=socket -u root ping --silent >/dev/null 2>&1; then break; fi
    if [ "$attempt" -eq 60 ]; then echo 'Demo database startup failed.' >&2; exit 1; fi
    sleep 1
done
exists=$(mariadb --protocol=socket -u root -Nse "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='threatpulse_public_demo'")
if [ "$exists" = 0 ]; then
    mariadb --protocol=socket -u root -e 'CREATE DATABASE threatpulse_public_demo CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
    mariadb --protocol=socket -u root threatpulse_public_demo < database.sql
    mariadb --protocol=socket -u root threatpulse_public_demo < database/bootstrap/01_siem_tables.sql
    for migration in database/migrations/*.sql; do
        mariadb --protocol=socket -u root threatpulse_public_demo < "$migration"
    done
    mariadb --protocol=socket -u root threatpulse_public_demo -e 'CREATE TABLE public_demo_ready (id INT PRIMARY KEY)'
fi
# Fail closed after any interrupted initialization rather than serving a partial schema.
mariadb --protocol=socket -u root threatpulse_public_demo -e 'SELECT id FROM public_demo_ready' >/dev/null
php deploy/public-demo-accounts.php
php database/verify_schema.php
php deploy/seed-public-demo.php
# Keep a small free instance bounded. No background feed traffic or cron in this mode.
cat > /etc/apache2/mods-available/mpm_prefork.conf <<'APACHE'
<IfModule mpm_prefork_module>
    StartServers 1
    MinSpareServers 1
    MaxSpareServers 2
    ServerLimit 2
    MaxRequestWorkers 2
    MaxConnectionsPerChild 500
</IfModule>
APACHE
printf 'memory_limit=96M\nmax_execution_time=30\n' > /usr/local/etc/php/conf.d/demo-limits.ini
# Do not make application source writable by the HTTP worker.
chown -R root:root /var/www/html
install -m 0640 -o www-data -g www-data /dev/null /var/www/html/fulllogs.log
exec apache2-foreground
