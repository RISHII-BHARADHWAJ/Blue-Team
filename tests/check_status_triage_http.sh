#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cistatus$(date +%s)$$"; csrf_token='ci-status-token'; base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
ids=$(docker compose exec -T web php -r '
require "includes/db.php";require "includes/soar/IncidentRepository.php";
$name="status-http-".bin2hex(random_bytes(5));
$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","admin"]);$user=(int)$pdo->lastInsertId();
$r=new IncidentRepository($pdo);$id=$r->create(["incident_number"=>$name,"title"=>$name]);$legacy=$r->create(["incident_number"=>$name."-legacy","title"=>$name]);echo $id." ".$legacy." ".$user;
')
set -- $ids
case_id="$1"; legacy_id="$2"; user_id="$3"
# The real database role is authoritative; change the disposable actor too.
set_session(){ docker compose exec -T -u www-data web php -r '
require "includes/db.php"; $pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute([$argv[2],(int)$argv[3]]);
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="status-http-reader";$_SESSION["role"]=$argv[2];$_SESSION["user_id"]=(int)$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();
' "$session_id" "$1" "$user_id" "$csrf_token"; }
post(){ curl --silent --show-error --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "id=$case_id&action=change_status&reason=HTTP+triage&$1" "$base/api/v1/incidents_detail.php"; }
[ "$(post 'new_status=OPEN&expected_status=NEW')" = 401 ]
set_session user
[ "$(post 'new_status=OPEN&expected_status=NEW')" = 403 ]
set_session analyst
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "id=$case_id&action=change_status&new_status=OPEN" "$base/api/v1/incidents_detail.php")" = 403 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php?id=$case_id")
printf '%s' "$page" | grep -q 'data-current-status="NEW"'
printf '%s' "$page" | grep -q 'expected_status: form.dataset.currentStatus'
printf '%s' "$page" | grep -q "reload.textContent = 'Reload case'"
for invalid in 'expected_status=' 'expected_status=UNKNOWN' 'expected_status[]=NEW'; do
  [ "$(post "new_status=OPEN&$invalid")" = 422 ]
done
for invalid in 'new_status[]=OPEN' 'new_status=UNKNOWN' 'new_status=OPEN&reason[]=bad'; do
  [ "$(post "$invalid&expected_status=NEW")" = 422 ]
done
for value in null true 1 '[]'; do
  [ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" -H 'Content-Type: application/json' --data "{\"id\":$case_id,\"action\":\"change_status\",\"new_status\":\"OPEN\",\"expected_status\":$value}" "$base/api/v1/incidents_detail.php")" = 422 ]
done
# The browser uses JSON; status values are normalized consistently with legacy transitions.
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" -H 'Content-Type: application/json' --data "{\"id\":$case_id,\"action\":\"change_status\",\"new_status\":\"open\",\"expected_status\":\" new \",\"reason\":\"Initial decision\"}" "$base/api/v1/incidents_detail.php")" = 200 ]
[ "$(post 'new_status=OPEN&expected_status=NEW')" = 200 ]
[ "$(post 'new_status=INVESTIGATING&expected_status=NEW')" = 409 ]
body=$(curl --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "id=$case_id&action=change_status&new_status=INVESTIGATING&expected_status=NEW" "$base/api/v1/incidents_detail.php")
printf '%s' "$body" | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true);if($r["success"]!==false||$r["error"]!=="status_conflict")exit(1);'
[ "$(post 'new_status=RESOLVED&expected_status=OPEN')" = 422 ]
[ "$(post 'new_status=CLOSED&expected_status=OPEN')" = 403 ]
set_session admin
[ "$(post 'new_status=CLOSED&expected_status=NEW')" = 409 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php?id=$case_id")
printf '%s' "$page" | grep -q 'data-current-status="OPEN"'
set_session analyst
[ "$(post 'new_status=INVESTIGATING&expected_status=OPEN')" = 200 ]
[ "$(post 'new_status=RESOLVED&expected_status=INVESTIGATING')" = 200 ]
set_session admin
[ "$(post 'new_status=CLOSED&expected_status=RESOLVED')" = 200 ]
[ "$(post 'new_status=CLOSED&expected_status=RESOLVED')" = 200 ]
[ "$(post 'new_status=OPEN&expected_status=CLOSED')" = 422 ]
set_session analyst
[ "$(post 'new_status=CLOSED&expected_status=RESOLVED')" = 403 ]
docker compose exec -T web php -r '
require "includes/db.php";
$s=$pdo->prepare("SELECT incident_number,status,resolved_at,closed_at FROM incidents WHERE id=?");$s->execute([(int)$argv[1]]);$c=$s->fetch();if($c["status"]!=="CLOSED"||!$c["resolved_at"]||!$c["closed_at"])exit(1);
$s=$pdo->prepare("SELECT COUNT(*) FROM incident_timeline WHERE incident_id=? AND event_type=?");$s->execute([(int)$argv[1],"STATUS_CHANGE"]);if((int)$s->fetchColumn()!==4)exit(1);
$s=$pdo->prepare("SELECT details FROM audit_log WHERE target=? AND action=? ORDER BY id");$s->execute([$c["incident_number"],"change_incident_status"]);$a=$s->fetchAll(PDO::FETCH_COLUMN);if(count($a)!==4||json_decode($a[0],true)["reason"]!=="Initial decision")exit(1);
' "$case_id"
case_id="$legacy_id"
[ "$(post 'new_status=OPEN')" = 200 ]
echo 'PASS: status HTTP authorization, CSRF, expected-state validation, JSON normalization, harmless replay, 409 conflicts, lifecycle permissions, audit counts and legacy clients'
