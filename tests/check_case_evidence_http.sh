#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cilink$(date +%s)$$";csrf_token='ci-case-evidence-token';base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-evidence.php?id=1")" = 302 ]
fixture=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r '
require "tests/event_escalation_fixtures.php";$name="link-http-".bin2hex(random_bytes(5));$manager=new IncidentManager($pdo);
$case=$manager->createIncident(["title"=>$name]);$simCase=$manager->createIncident(["title"=>$name." sim","is_simulated"=>true]);
$uid=escalationUser($pdo,$name);$reader=escalationUser($pdo,$name."-reader","user");$ids=[];for($i=0;$i<26;$i++)$ids[]=escalationFixture($pdo,$name."-".$i);
$sim=escalationFixture($pdo,$name."-sim",true);$legacy=escalationFixture($pdo,$name."-legacy",false,true);
echo $case["id"]." ".$simCase["id"]." ".$uid." ".$reader." ".$ids[0]." ".$ids[1]." ".$sim." ".$legacy." ".$name;
')
set -- $fixture
case_id="$1";sim_case="$2";uid="$3";reader="$4";log_id="$5";new_log="$6";sim_log="$7";legacy="$8";name="$9"
set_session(){ docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="api_automation";$_SESSION["role"]=$argv[3];$_SESSION["csrf_token"]=$argv[4];if($argv[2]==="0")unset($_SESSION["user_id"]);else $_SESSION["user_id"]=(int)$argv[2];session_write_close();
' "$session_id" "$1" "$2" "$csrf_token"; }
post(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$1" "$base/incident-evidence.php"; }
get_status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-evidence.php?$1"; }
set_session "$reader" user
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-evidence.php?id=$case_id&log_id=$log_id")
printf '%s' "$page" | grep -q 'A named Tier 2 or higher analyst'
if printf '%s' "$page" | grep -q 'Link event and save reason';then exit 1;fi
[ "$(post "id=$case_id&log_id=$log_id&reason=Reason")" = 403 ]
set_session "$reader" admin
[ "$(post "id=$case_id&log_id=$log_id&reason=Reason")" = 403 ]
set_session 0 analyst
[ "$(post "id=$case_id&log_id=$log_id&reason=Reason")" = 403 ]
set_session "$uid" analyst
[ "$(get_status "id=$sim_case")" = 422 ]
[ "$(get_status "id=$case_id&log_id=$sim_log")" = 422 ]
[ "$(get_status "id=$case_id&log_id=$legacy")" = 404 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-evidence.php?id=$case_id&q=$name&page=999&log_id=$log_id")
printf '%s' "$page" | grep -q 'Page 2 of 2'
printf '%s' "$page" | grep -q '&lt;script&gt;eventProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q "id=$case_id&amp;q=$name"
printf '%s' "$page" | grep -q 'Link event and save reason'
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "id=$case_id&log_id=$log_id&reason=Reason" "$base/incident-evidence.php")
[ "$status" = 403 ]
[ "$(post "id=$case_id&log_id=$log_id&reason=Reason&author_id=$reader")" = 422 ]
[ "$(post "id=$case_id&log_id=$log_id&reason=")" = 422 ]
[ "$(post "id=$case_id&log_id=$log_id&reason=Case+evidence+reason")" = 303 ]
[ "$(post "id=$case_id&log_id=$log_id&reason=Replay")" = 303 ]
page=$(curl --fail --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-evidence.php?id=$case_id&log_id=$log_id")
printf '%s' "$page" | grep -q 'Already linked to this case'
printf '%s' "$page" | grep -q 'No duplicate note or link was created'
docker compose exec -T web php -r 'require "includes/db.php";$pdo->prepare("UPDATE incidents SET status=? WHERE id=?")->execute(["CLOSED",(int)$argv[1]]);' "$case_id"
[ "$(post "id=$case_id&log_id=$log_id&reason=Replay+closed")" = 303 ]
[ "$(post "id=$case_id&log_id=$new_log&reason=Closed+case")" = 409 ]
docker compose exec -T web php -r '
require "includes/db.php";foreach(["incident_alerts","case_notes"] as $table){$stmt=$pdo->prepare("SELECT COUNT(*) FROM $table WHERE incident_id=?");$stmt->execute([(int)$argv[1]]);if((int)$stmt->fetchColumn()!==1)exit(1);}
' "$case_id"
echo 'PASS: case evidence HTTP viewer access, named roles, CSRF, simulation/legacy exclusion, pagination, escaping, strict input, replay and closed-case conflict'
