#!/bin/sh
# Disposable Compose CI only. Tests use sessions with unguessable IDs.
set -eu
session_id="cidetections$(date +%s)$$"
csrf_token="ci-detection-token"
cleanup() {
 docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION"); session_id($argv[1]); session_start(); session_destroy();
 ' "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT
endpoint='http://localhost:8080/detections.php'
status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$endpoint")
[ "$status" = 302 ] || { echo 'Anonymous detection access accepted'; exit 1; }
ids=$(docker compose exec -T web php -r '
 require "includes/db.php"; require "includes/soar/SiemSoarAlertPipeline.php";
 $name="detections-http-".bin2hex(random_bytes(6));
 $pdo->prepare("INSERT INTO users (username,password,role) VALUES (?, ?, ?)")->execute([$name,"not-a-login-hash","admin"]);
 $userId=(int)$pdo->lastInsertId(); $pipeline=new SiemSoarAlertPipeline($pdo);
 for ($i=0;$i<5;$i++) $r=$pipeline->ingest(["source"=>$name,"source_event_id"=>(string)$i,
 "source_ip"=>"192.0.2.79","severity"=>"LOW","is_simulated"=>true,"message"=>"Rejected",
 "metadata"=>["event_type"=>"authentication","outcome"=>"failure"]],"ci-detections");
 echo $userId." ".$r["detections"][0]["id"];
')
set -- $ids
user_id="$1"
finding_id="$2"
set_role() {
 docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION"); session_id($argv[1]); session_start();
 $_SESSION["analyst"]="ci-detections"; $_SESSION["user_id"]=(int)$argv[2];
 $_SESSION["role"]=$argv[3]; $_SESSION["csrf_token"]=$argv[4]; session_write_close();
 ' "$session_id" "$user_id" "$1" "$csrf_token"
}
set_role user
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$endpoint?id=$finding_id&kind=simulated")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q 'Inspect log #'
if printf '%s' "$page" | grep -q 'name="rule_key"'; then echo 'Reader received settings forms'; exit 1; fi
settings='rule_key=auth_failures&enabled=1&severity=HIGH&threshold_count=5&window_seconds=300&revision=1'
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings" "$endpoint")
[ "$status" = 403 ] || { echo 'Non-admin changed rules'; exit 1; }
set_role admin
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "$settings" "$endpoint")
[ "$status" = 403 ] || { echo 'Admin update without CSRF accepted'; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings&window_seconds=1" "$endpoint")
[ "$status" = 422 ] || { echo "Invalid window accepted: $status"; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings" "$endpoint")
[ "$status" = 303 ] || { echo "Admin settings save failed: $status"; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings" "$endpoint")
[ "$status" = 409 ] || { echo 'Stale settings overwrite accepted'; exit 1; }
# Verify the service rechecks current DB role even when the session still says admin.
docker compose exec -T web php -r 'require "includes/db.php"; $pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute(["user",(int)$argv[1]]);' "$user_id"
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$settings&revision=2" "$endpoint")
[ "$status" = 403 ] || { echo 'Revoked administrator changed rules'; exit 1; }
# Submit a full simulated threshold through HTTP, then inspect escaped finding context.
source="http-detection-$session_id"
i=1
while [ "$i" -le 5 ]; do
 payload="{\"source\":\"$source<script>probe()</script>\",\"source_event_id\":\"$i\",\"source_ip\":\"192.0.2.81\",\"event_timestamp\":\"2026-10-21T00:00:00Z\",\"severity\":\"LOW\",\"message\":\"Rejected\",\"is_simulated\":true,\"metadata\":{\"event_type\":\"authentication\",\"outcome\":\"failure\"}}"
 response=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" -H 'Content-Type: application/json' --data "$payload" 'http://localhost:8080/api/v1/alerts.php')
 i=$((i+1))
done
finding_id=$(printf '%s' "$response" | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true); if(empty($r["detections"][0]["id"]) || $r["correlation"]["incident_id"]!==null) exit(1); echo $r["detections"][0]["id"];')
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$endpoint?id=$finding_id&kind=simulated")
printf '%s' "$page" | grep -q '&lt;script&gt;probe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>probe()</script>'; then echo 'Unescaped finding context'; exit 1; fi
response=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" -H 'Content-Type: application/json' --data "$payload" 'http://localhost:8080/api/v1/alerts.php')
printf '%s' "$response" | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true); if(empty($r["duplicate"])) exit(1);'
echo 'PASS: detection read access, admin/CSRF enforcement, validation, revision conflicts, revoked roles, HTTP ingestion and safe rendering'
