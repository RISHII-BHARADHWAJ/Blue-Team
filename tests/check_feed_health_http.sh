#!/bin/sh
# Disposable Compose CI only; no external collection is performed.
set -eu
session_id="cifeeds$(date +%s)$$"
csrf_token='ci-feed-csrf'
endpoint='http://localhost:8080/feeds.php'
cleanup() {
 docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT
status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$endpoint")
[ "$status" = 302 ] || { echo 'Anonymous history access accepted'; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://localhost:8080/live_status.php)
[ "$status" = 401 ] || { echo 'Anonymous live status accepted'; exit 1; }
user_id=$(docker compose exec -T web php -r '
 require "includes/db.php";
 $name="<script>feedProbe()</script>".bin2hex(random_bytes(4));
 $pdo->prepare("INSERT INTO users (username,password,role) VALUES (?, ?, ?)")->execute([$name,"not-a-login-hash","admin"]);echo $pdo->lastInsertId();
')
# The real database role is authoritative; change the disposable actor too.
set_role() {
 docker compose exec -T -u www-data web php -r '
 require "includes/db.php"; $pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute([$argv[3],(int)$argv[2]]);
 session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();
 $_SESSION["analyst"]="ci-feeds";$_SESSION["user_id"]=(int)$argv[2];$_SESSION["role"]=$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();
 ' "$session_id" "$user_id" "$1" "$csrf_token"
}
set_role user
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$endpoint?provider=emerging_threats&status=FAILED")
printf '%s' "$page" | grep -q 'Collection history'
printf '%s' "$page" | grep -q 'FAILED'
if printf '%s' "$page" | grep -q 'name="refresh_seconds"'; then echo 'Reader received configuration form'; exit 1; fi
settings='provider=cins_army&enabled=1&refresh_seconds=600&revision=1'
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings" "$endpoint")
[ "$status" = 403 ] || { echo 'Reader changed feed settings'; exit 1; }
set_role admin
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "$settings" "$endpoint")
[ "$status" = 403 ] || { echo 'CSRF-free feed update accepted'; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings&refresh_seconds=1" "$endpoint")
[ "$status" = 422 ] || { echo 'Invalid refresh interval accepted'; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings&provider=http://localhost" "$endpoint")
[ "$status" = 422 ] || { echo 'Arbitrary endpoint accepted'; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings" "$endpoint")
[ "$status" = 303 ] || { echo "Admin configuration failed: $status"; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings" "$endpoint")
[ "$status" = 409 ] || { echo 'Stale revision accepted'; exit 1; }
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$endpoint")
printf '%s' "$page" | grep -q '&lt;script&gt;feedProbe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>feedProbe()</script>'; then echo 'Unescaped audit identity'; exit 1; fi
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" http://localhost:8080/soc.php)
printf '%s' "$page" | grep -q 'Collection history'
curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" http://localhost:8080/live_status.php | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true);if(($r["last_fetch"]["status"]??null)!=="success")exit(1);'
# CLI deployment pause avoids network access even when a collector is manually invoked.
docker compose exec -T web php api_fetch.php | grep -q 'Collection paused'
for path in api_fetch.php feodo_realtime.php; do
 status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "http://localhost:8080/$path")
 [ "$status" = 405 ] || { echo 'Collector exposed over HTTP'; exit 1; }
done
echo 'PASS: feed history read access, admin settings, CSRF, revisions, fixed endpoints, escaped identity, SOC/live status and deployment pause'
