#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cihandoff$(date +%s)$$";csrf_token='ci-handoff-token';base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
ids=$(docker compose exec -T web php -r '
require "includes/db.php";require "includes/soar/IncidentManager.php";$name="handoff-http-".bin2hex(random_bytes(5));$users=[];
foreach(["a","b"] as $suffix){$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name.$suffix,"not-a-login-hash","analyst"]);$users[]=(int)$pdo->lastInsertId();}
$case=(new IncidentManager($pdo))->createIncident(["title"=>$name]);echo $case["id"]." ".$users[0]." ".$users[1];
')
set -- $ids
case_id="$1";user_a="$2";user_b="$3"
# The real database role is authoritative; change the disposable actor too.
set_session(){ docker compose exec -T -u www-data web php -r '
require "includes/db.php"; $pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute([$argv[2],(int)$argv[3]]);
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="api_automation";$_SESSION["role"]=$argv[2];$_SESSION["user_id"]=(int)$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();
' "$session_id" "$1" "$2" "$csrf_token"; }
post(){ curl --silent --show-error --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "id=$case_id&action=assign&$1" "$base/api/v1/incidents_detail.php"; }
set_session user "$user_a"
[ "$(post "analyst_id=$user_a&expected_assigned_to=")" = 403 ]
set_session analyst "$user_a"
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "id=$case_id&action=assign&analyst_id=$user_a" "$base/api/v1/incidents_detail.php")
[ "$status" = 403 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php?id=$case_id")
printf '%s' "$page" | grep -q 'data-assigned-to=""'
printf '%s' "$page" | grep -q 'expected_assigned_to:'
for invalid in '-1' 'unknown' '0';do [ "$(post "analyst_id=$user_a&expected_assigned_to=$invalid")" = 422 ];done
[ "$(post "analyst_id=$user_a&expected_assigned_to[]=1")" = 422 ]
# Browser sends JSON null for the initially unassigned owner.
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" -H 'Content-Type: application/json' --data "{\"id\":$case_id,\"action\":\"assign\",\"analyst_id\":$user_a,\"expected_assigned_to\":null}" "$base/api/v1/incidents_detail.php")
[ "$status" = 200 ]
[ "$(post "analyst_id=$user_a&expected_assigned_to=")" = 200 ]
[ "$(post "analyst_id=$user_b&expected_assigned_to=")" = 409 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php?id=$case_id")
printf '%s' "$page" | grep -q "data-assigned-to=\"$user_a\""
[ "$(post "analyst_id=$user_b&expected_assigned_to=$user_a")" = 200 ]
set_session analyst "$user_b"
json=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/notifications.php?unread_only=1")
printf '%s' "$json" | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true);if(!$r["success"]||$r["count"]!==1||$r["data"][0]["type"]!=="INCIDENT_ASSIGNED"||(int)$r["data"][0]["incident_id"]!==(int)$argv[1])exit(1);' "$case_id"
docker compose exec -T web php -r '
require "includes/db.php";$stmt=$pdo->prepare("SELECT COUNT(*) FROM notifications WHERE incident_id=?");$stmt->execute([(int)$argv[1]]);if((int)$stmt->fetchColumn()!==2)exit(1);
' "$case_id"
# Omitted expectation retains compatibility with old clients.
[ "$(post "analyst_id=$user_a")" = 200 ]
echo 'PASS: assignment HTTP role/CSRF gates, expected-owner validation, JSON null, replay, 409 conflict, UI guard, recipient inbox and legacy clients'
