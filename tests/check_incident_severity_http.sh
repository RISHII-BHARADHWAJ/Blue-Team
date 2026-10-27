#!/bin/sh
set -eu
base='http://localhost:8080';session_id="ciseverity$(date +%s)$$";token='severity-ci-csrf'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/api/v1/incident_severity.php")" = 401 ]
fixture=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r '
require "tests/audit_history_fixtures.php";$name="severity-http-".bin2hex(random_bytes(5));$admin=auditUser($pdo,$name."-admin","admin");$lead=auditUser($pdo,$name."-lead","lead");$analyst=auditUser($pdo,$name."-analyst","analyst");$reader=auditUser($pdo,$name."-reader","user");$m=new IncidentManager($pdo);$case=$m->createIncident(["title"=>$name]);$sim=$m->createIncident(["title"=>$name,"is_simulated"=>true]);echo implode(" ",[$admin,$lead,$analyst,$reader,$case["id"],$sim["id"]]);')
set -- $fixture;admin="$1";lead="$2";analyst="$3";reader="$4";id="$5";sim="$6"
set_session(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="severity-http";$_SESSION["role"]=$argv[2];$_SESSION["user_id"]=(int)$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();' "$session_id" "$1" "$2" "$token"; }
post_status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H 'Content-Type: application/json' -H "X-CSRF-Token: $token" --data "$1" "$base/api/v1/incident_severity.php"; }
post(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H 'Content-Type: application/json' -H "X-CSRF-Token: $token" --data "$1" "$base/api/v1/incident_severity.php"; }
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
body="{\"incident_id\":$id,\"severity\":\"HIGH\",\"expected_severity\":\"MEDIUM\",\"expected_priority\":\"P3\",\"reason\":\"<script>severityProbe()</script>\"}"
for uid in "$analyst" "$reader";do set_session admin "$uid";[ "$(post_status "$body")" = 403 ];done
for uid in 0 2147483647;do set_session admin "$uid";[ "$(post_status "$body")" = 401 ];done
set_session lead "$lead"
page=$(get "incidents.php?id=$id");printf '%s' "$page" | grep -q 'id="severity-form"'
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H 'Content-Type: application/json' --data "$body" "$base/api/v1/incident_severity.php")" = 403 ]
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/incident_severity.php")" = 405 ]
post "$body" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["success"] and d["data"]["changed"] and d["data"]["incident"]["severity"]=="HIGH" and d["data"]["incident"]["priority"]=="P2" and d["data"]["note_id"]'
post "$body" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["success"] and not d["data"]["changed"] and d["data"]["note_id"] is None'
page=$(get "incidents.php?id=$id")
printf '%s' "$page" | grep -q '&lt;script&gt;severityProbe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>severityProbe()';then exit 1;fi
stale="{\"incident_id\":$id,\"severity\":\"LOW\",\"expected_severity\":\"MEDIUM\",\"expected_priority\":\"P3\",\"reason\":\"Stale page\"}"
[ "$(post_status "$stale")" = 409 ]
for invalid in '{}' '[]' 'null' '{bad' ;do code=$(post_status "$invalid");case "$code" in 400|422) ;; *) exit 1;; esac;done
for extra in '"author_id":1' '"priority":"P1"' '"actor":"admin"' '"severity":[]';do
  malformed="{\"incident_id\":$id,\"severity\":\"LOW\",\"expected_severity\":\"HIGH\",\"expected_priority\":\"P2\",\"reason\":\"Reason\",$extra}"
  [ "$(post_status "$malformed")" = 422 ]
done
[ "$(post_status '{"incident_id":2147483647,"severity":"LOW","expected_severity":"MEDIUM","expected_priority":"P3","reason":"Missing case"}')" = 404 ]
# Database role is authoritative, including stale lower/higher session tiers.
set_session user "$admin"
post "{\"incident_id\":$sim,\"severity\":\"CRITICAL\",\"expected_severity\":\"MEDIUM\",\"expected_priority\":\"P3\",\"reason\":\"Training assessment\"}" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["data"]["changed"] and int(d["data"]["incident"]["is_simulated"])==1'
docker compose exec -T web php -r 'require "includes/db.php";$pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute(["user",(int)$argv[1]]);' "$lead"
set_session lead "$lead";[ "$(post_status "$body")" = 403 ]
set_session admin "$admin"
docker compose exec -T web php -r 'require "includes/db.php";$pdo->prepare("UPDATE incidents SET status=? WHERE id=?")->execute(["CLOSED",(int)$argv[1]]);' "$id"
[ "$(post_status "$body")" = 409 ]
page=$(get "incidents.php?id=$id");if printf '%s' "$page" | grep -q 'id="severity-form"';then exit 1;fi
set_session user "$reader"
page=$(get "incidents.php?id=$sim");if printf '%s' "$page" | grep -q 'id="severity-form"';then exit 1;fi
echo 'PASS: severity HTTP roles, CSRF, attributed notes, escaped reason, retries, stale values, closed cases, simulation and request validation'
