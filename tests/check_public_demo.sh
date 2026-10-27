#!/bin/sh
# Isolated CI image/container; never uses the local Compose database or user secrets.
set -eu
name='threatpulse-public-demo-ci'
cleanup(){ docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker build -t threatpulse-public-demo-ci .
docker run -d --name "$name" --memory=512m --cpus=1 -p 127.0.0.1:8081:10000 \
  -e APP_ENV=public-demo -e DB_NAME=threatpulse_public_demo -e DB_USER=demo_app \
  -e SESSION_COOKIE_SECURE=1 -e FEED_COLLECTION_ENABLED=0 \
  -e DB_PASS=ci-only-database-secret-0123456789abcdef \
  -e PUBLIC_DEMO_ADMIN_PASSWORD=ci-only-admin-secret-0123456789abcdef \
  threatpulse-public-demo-ci >/dev/null
attempt=0
until curl --fail --silent http://127.0.0.1:8081/health.php >/dev/null; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then docker logs "$name"; exit 1; fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 90 ]; then docker logs "$name"; exit 1; fi
  sleep 2
done
docker exec "$name" php database/verify_schema.php
docker exec "$name" php -r '
require "includes/db.php";
$users=$pdo->query("SELECT username,password FROM users")->fetchAll(PDO::FETCH_KEY_PAIR);
if(!password_verify(getenv("PUBLIC_DEMO_ADMIN_PASSWORD"),$users["admin"]) || password_verify("ChangeMe123!",$users["admin"]) || password_verify("kali",$users["analyst"]))exit(1);
if((int)$pdo->query("SELECT COUNT(*) FROM demo_sessions")->fetchColumn()!==1)exit(1);
try{$pdo->exec("CREATE TABLE forbidden_ddl (id INT)");exit(1);}catch(PDOException $expected){}
'
curl --fail --silent -D /tmp/public-demo-headers http://127.0.0.1:8081/login.php -o /tmp/public-demo-login
grep -qi 'secure' /tmp/public-demo-headers
grep -q 'Temporary demo: saved data resets' /tmp/public-demo-login
[ "$(curl --silent -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/deploy/public-demo-accounts.php)" = 403 ]
docker exec -u www-data "$name" test ! -w /var/www/html/login.php
# Startup is repeatable on the same container without duplicate schemas or seeded cases.
docker restart "$name" >/dev/null
attempt=0
until curl --fail --silent http://127.0.0.1:8081/health.php >/dev/null; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then docker logs "$name"; exit 1; fi
  attempt=$((attempt + 1)); if [ "$attempt" -ge 90 ]; then docker logs "$name"; exit 1; fi
  sleep 2
done
docker exec "$name" php -r 'require "includes/db.php";if((int)$pdo->query("SELECT COUNT(*) FROM demo_sessions")->fetchColumn()!==1)exit(1);'
echo 'PASS: 512 MiB public-demo startup, full schema, private accounts, least-privilege DB, secure cookies, protected source, seeded training case, repeat startup'
