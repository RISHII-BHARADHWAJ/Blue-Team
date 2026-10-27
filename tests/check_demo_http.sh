#!/bin/sh
# Disposable Compose CI only; verifies browser auth, CSRF, retry and rendering paths.
set -eu
session_id="cidemo$(date +%s)$$"
csrf_token="ci-demo-token"
endpoint='http://localhost:8080/demo.php'
cleanup() {
 docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT
status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$endpoint")
[ "$status" = 302 ] || { echo 'Anonymous demo access accepted'; exit 1; }
user_id=$(docker compose exec -T web php -r '
 require "includes/db.php";
 $pdo->prepare("INSERT INTO users (username,password,role) VALUES (?, ?, ?)")->execute(["demo-http-".bin2hex(random_bytes(6)),"not-a-login-hash","admin"]);
 echo $pdo->lastInsertId();
')
# The real database role is authoritative; change the disposable actor too.
set_role() {
 docker compose exec -T -u www-data web php -r '
 require "includes/db.php"; $pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute([$argv[3],(int)$argv[2]]);
 session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();
 $_SESSION["analyst"]="ci-demo";$_SESSION["user_id"]=(int)$argv[2];$_SESSION["role"]=$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();
 ' "$session_id" "$user_id" "$1" "$csrf_token"
}
post_status() {
 curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$1" "$endpoint"
}
set_role user
key='00000000000000000000000000000001'
[ "$(post_status "action=create&request_key=$key")" = 403 ] || { echo 'Reader created demo';exit 1; }
set_role admin
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "action=create&request_key=$key" "$endpoint")
[ "$status" = 403 ] || { echo 'Missing CSRF accepted';exit 1; }
[ "$(post_status 'action=create&request_key=invalid')" = 422 ] || { echo 'Invalid key accepted';exit 1; }
[ "$(post_status "action=create&request_key=$key")" = 303 ] || { echo 'Demo creation failed';exit 1; }
[ "$(post_status "action=create&request_key=$key")" = 303 ] || { echo 'Demo retry failed';exit 1; }
ids=$(docker compose exec -T web php -r '
 require "includes/db.php";
 $s=$pdo->prepare("SELECT id,incident_id FROM demo_sessions WHERE created_by=? AND request_key=?");$s->execute([(int)$argv[1],$argv[2]]);$rows=$s->fetchAll();
 if(count($rows)!==1)exit(1);echo $rows[0]["id"]." ".$rows[0]["incident_id"];
' "$user_id" "$key")
set -- $ids
demo_id="$1"
incident_id="$2"
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$endpoint?id=$demo_id")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q 'Run safe playbook preview'
[ "$(post_status "action=preview&session_id=$demo_id")" = 303 ] || { echo 'Preview failed';exit 1; }
[ "$(post_status "action=preview&session_id=$demo_id")" = 303 ] || { echo 'Preview retry failed';exit 1; }
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$endpoint?id=$demo_id")
printf '%s' "$page" | grep -q 'COMPLETED'
printf '%s' "$page" | grep -q 'Would request approval; simulated cases do not create approval requests.'
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "http://localhost:8080/incidents.php?kind=simulated&id=$incident_id")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q 'Continue the simulated walkthrough'
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" -H 'Content-Type: application/json' --data "{\"incident_id\":$incident_id}" 'http://localhost:8080/api/v1/incidents_enrichment.php')
[ "$status" = 409 ] || { echo 'Live simulated enrichment accepted';exit 1; }
# Revoke the DB role while retaining the admin session to test service recheck.
docker compose exec -T web php -r 'require "includes/db.php";$pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute(["user",(int)$argv[1]]);' "$user_id"
[ "$(post_status 'action=create&request_key=00000000000000000000000000000002')" = 403 ] || { echo 'Revoked role created demo';exit 1; }
echo 'PASS: demo HTTP login, role, CSRF, validation, idempotency, preview results, case links and enrichment boundary'
