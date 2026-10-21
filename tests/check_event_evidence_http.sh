#!/bin/sh
# Only invoke on the disposable Compose CI stack.
set -eu
session_id="cievidence$(date +%s)$$"
cleanup() {
  docker compose exec -T -u www-data web php -r '
    session_name("CYBERTECH_SECURE_SESSION"); session_id($argv[1]); session_start(); session_destroy();
  ' "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT
status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://localhost:8080/events.php)
[ "$status" = 302 ] || { echo "Anonymous event access was not redirected" >&2; exit 1; }
docker compose exec -T -u www-data web php -r '
  session_name("CYBERTECH_SECURE_SESSION"); session_id($argv[1]); session_start();
  $_SESSION["analyst"]="ci-evidence"; $_SESSION["role"]="user"; session_write_close();
' "$session_id"
log_id=$(docker compose exec -T web php -r '
  require "includes/db.php"; require "includes/soar/SiemSoarAlertPipeline.php";
  $r=(new SiemSoarAlertPipeline($pdo))->ingest([
    "source"=>"ci-ui", "source_event_id"=>bin2hex(random_bytes(8)), "is_simulated"=>true,
    "message"=>"<script>alert(123)</script>", "severity"=>"INFO"
  ], "ci-evidence"); echo $r["log_id"];
')
case "$log_id" in ''|*[!0-9]*) echo "Invalid evidence fixture ID" >&2; exit 1 ;; esac
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "http://localhost:8080/events.php?log_id=$log_id")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q '&lt;script&gt;alert(123)&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>alert(123)</script>'; then echo 'Unescaped evidence rendered' >&2; exit 1; fi
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" 'http://localhost:8080/events.php?from=invalid')
[ "$status" = 400 ] || { echo "Invalid dates were not rejected" >&2; exit 1; }
echo 'PASS: evidence authentication, read access, simulation labeling, escaped payload, date validation'
