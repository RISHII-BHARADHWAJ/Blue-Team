#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="ciescalate$(date +%s)$$";csrf_token='ci-escalate-token';base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/event-escalate.php?log_id=1")" = 302 ]
ids=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r '
require "tests/event_escalation_fixtures.php";$name="escalate-http-".bin2hex(random_bytes(5));
echo escalationUser($pdo,$name)." ".escalationUser($pdo,$name."-reader","user")." ".escalationFixture($pdo,$name)." ".escalationFixture($pdo,$name."-sim",true)." ".escalationFixture($pdo,$name."-legacy",false,true);
')
set -- $ids
uid="$1";reader="$2";log_id="$3";sim_id="$4";legacy_id="$5"
set_session(){ docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="api_automation";$_SESSION["role"]="admin";$_SESSION["csrf_token"]=$argv[3];if($argv[2]==="0")unset($_SESSION["user_id"]);else $_SESSION["user_id"]=(int)$argv[2];session_write_close();
' "$session_id" "$1" "$csrf_token"; }
get_status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/event-escalate.php?log_id=$1"; }
post(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$1" "$base/event-escalate.php"; }
set_session "$reader"
[ "$(get_status "$log_id")" = 403 ]
[ "$(post "log_id=$log_id&title=Title&reason=Reason")" = 403 ]
set_session 0
[ "$(get_status "$log_id")" = 403 ]
set_session "$uid"
[ "$(get_status "$sim_id")" = 422 ]
[ "$(get_status "$legacy_id")" = 404 ]
[ "$(get_status 2147483647)" = 404 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/event-escalate.php?log_id=$log_id")
printf '%s' "$page" | grep -q '&lt;script&gt;eventProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q 'Create investigation case'
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "log_id=$log_id&title=Title&reason=Reason" "$base/event-escalate.php")
[ "$status" = 403 ]
[ "$(post "log_id=$log_id&title=Title&reason=")" = 422 ]
[ "$(post "log_id=$log_id&title=Title&reason=Reason&user_id=$reader")" = 422 ]
[ "$(post "log_id=$sim_id&title=Title&reason=Reason")" = 422 ]
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "log_id=$log_id&title=HTTP+case&reason=Investigate+this+evidence" "$base/event-escalate.php")
printf '%s' "$headers" | grep -q '303 See Other'
printf '%s' "$headers" | grep -qi 'Location: incidents.php?id='
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
[ "$(post "log_id=$log_id&title=Replay&reason=Replay")" = 303 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/event-escalate.php?log_id=$log_id")
printf '%s' "$page" | grep -q 'Already linked to a case'
if printf '%s' "$page" | grep -q 'Create investigation case';then exit 1;fi
docker compose exec -T web php -r '
require "includes/db.php";$stmt=$pdo->prepare("SELECT COUNT(*),MIN(incident_id) FROM incident_alerts WHERE log_id=?");$stmt->execute([(int)$argv[1]]);$row=$stmt->fetch(PDO::FETCH_NUM);if((int)$row[0]!==1)exit(1);
$stmt=$pdo->prepare("SELECT COUNT(*) FROM case_notes WHERE incident_id=? AND author_id=?");$stmt->execute([(int)$row[1],(int)$argv[2]]);if((int)$stmt->fetchColumn()!==1)exit(1);
' "$log_id" "$uid"
docker compose exec -T web php -r '
putenv("THREATPULSE_API_KEY=ci_escalation_bearer_123456");$_SERVER["HTTP_AUTHORIZATION"]="Bearer ci_escalation_bearer_123456";$_SERVER["REQUEST_METHOD"]="GET";
register_shutdown_function(function(){if(http_response_code()!==403)exit(1);});require "event-escalate.php";
' >/dev/null
echo 'PASS: event escalation HTTP named roles, CSRF, evidence classification, strict input, escaping, redirect, replay and bearer exclusion'
