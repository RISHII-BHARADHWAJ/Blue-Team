#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="ciinbox$(date +%s)$$";csrf_token='ci-inbox-token';base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/notifications.php")" = 302 ] || exit 1
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/api/v1/notifications.php")" = 401 ] || exit 1
ids=$(docker compose exec -T web php -r '
 require "includes/db.php";require "includes/soar/notifications/NotificationService.php";require "includes/soar/IncidentManager.php";
 $name="inbox_http_".bin2hex(random_bytes(5));$users=[];foreach(["a","b"] as $suffix){$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name.$suffix,"not-a-login-hash","user"]);$users[]=(int)$pdo->lastInsertId();}[$a,$b]=$users;
 $case=(new IncidentManager($pdo))->createIncident(["title"=>"Inbox fixture","is_simulated"=>true]);
 $s=new NotificationService($pdo);if(!$s->notify($a,"PLAYBOOK_COMPLETED","<script>probe()</script>","token: HIDDEN_SECRET",["incident_id"=>$case["id"]]))exit(1);$own=(int)$pdo->lastInsertId();
 $pdo->prepare("INSERT INTO notifications (user_id,recipient_id,title,message,notification_type) VALUES (?,?,?,?,?)")->execute([$a,$b,"OTHER_USER_MESSAGE","other","INCIDENT_ASSIGNED"]);$foreign=(int)$pdo->lastInsertId();
 echo $a." ".$b." ".$own." ".$foreign;
')
set -- $ids
user_id="$1";other_id="$2";own_id="$3";foreign_id="$4"
set_session(){ docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="api_automation";$_SESSION["role"]="admin";$_SESSION["csrf_token"]=$argv[3];
 if($argv[2]==="0")unset($_SESSION["user_id"]);else $_SESSION["user_id"]=(int)$argv[2];session_write_close();
 ' "$session_id" "$1" "$csrf_token"; }
set_session "$user_id"
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/notifications.php?filter=all")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q '&lt;script&gt;probe()&lt;/script&gt;'
if printf '%s' "$page" | grep -Eq '<script>probe|OTHER_USER_MESSAGE|HIDDEN_SECRET';then echo 'Unsafe inbox HTML';exit 1;fi
json=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/notifications.php?unread_only=1&limit=10")
printf '%s' "$json" | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true);if(!$r["success"]||$r["count"]!==1||$r["unread_count"]!==1)exit(1);'
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/notifications.php")
printf '%s' "$headers" | grep -qi 'Content-Type: application/json'
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
post(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$2" "$base/$1"; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "notification_id=$own_id" "$base/api/v1/notifications.php")
[ "$status" = 403 ] || { echo 'Display name bypassed CSRF';exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/notifications.php?user_id=$other_id")
[ "$status" = 403 ] || { echo 'Admin cross-user read accepted';exit 1; }
[ "$(post api/v1/notifications.php "notification_id=$foreign_id")" = 404 ] || { echo 'Foreign acknowledgement accepted';exit 1; }
[ "$(post notifications.php "notification_ids[]=$own_id&notification_ids[]=$foreign_id")" = 404 ] || exit 1
[ "$(post api/v1/notifications.php "notification_id=$own_id&user_id=$other_id")" = 422 ] || exit 1
[ "$(post api/v1/notifications.php "notification_id=$own_id")" = 200 ] || exit 1
[ "$(post api/v1/notifications.php "notification_id=$own_id")" = 200 ] || { echo 'Acknowledgement replay failed';exit 1; }
[ "$(post notifications.php "notification_id=$own_id&filter=all")" = 303 ] || exit 1
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/notifications.php?filter=read")
printf '%s' "$page" | grep -q '1 matching notifications'
set_session 0
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/notifications.php")
[ "$status" = 403 ] || { echo 'Nameless session fell back to account 1';exit 1; }
set_session 2147483647
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/notifications.php")
[ "$status" = 302 ] || exit 1
# Exercise a valid bearer credential in a fresh PHP request context: personal inbox still requires a named session.
docker compose exec -T web php -r '
 putenv("THREATPULSE_API_KEY=ci_inbox_bearer_123456789");$_SERVER["HTTP_AUTHORIZATION"]="Bearer ci_inbox_bearer_123456789";$_SERVER["REQUEST_METHOD"]="GET";
 register_shutdown_function(function(){if(http_response_code()!==403)exit(1);});require "api/v1/notifications.php";
' >/dev/null
echo 'PASS: inbox HTTP named ownership, API content type, no fallback identity, CSRF, admin isolation, atomic batch, replay, escaping and bearer exclusion'
