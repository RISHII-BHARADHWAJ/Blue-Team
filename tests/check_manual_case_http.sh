#!/bin/sh
set -eu
base='http://localhost:8080';session_id="ciintake$(date +%s)$$";csrf_token='ci-intake-token'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-new.php")" = 302 ]
fixture=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r 'require "tests/audit_history_fixtures.php";$name="intake-http-".bin2hex(random_bytes(5));echo auditUser($pdo,$name."-analyst","analyst")." ".auditUser($pdo,$name."-reader","user");')
set -- $fixture;analyst="$1";reader="$2"
set_session(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="intake-session-alias";$_SESSION["role"]=$argv[2];$_SESSION["user_id"]=(int)$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();' "$session_id" "$1" "$2" "$csrf_token"; }
status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
post_status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$1" "$base/incident-new.php"; }
for uid in "$reader";do set_session admin "$uid";[ "$(status 'incident-new.php')" = 403 ];done
for uid in 0 2147483647;do set_session admin "$uid";[ "$(status 'incident-new.php')" = 302 ];done
# Current database role can grant access despite a stale lower session role.
set_session user "$analyst"
page=$(get 'incident-new.php')
printf '%s' "$page" | grep -q 'Create case and save report'
key=$(printf '%s' "$page" | python3 -c 'import re,sys;print(re.search(r"name=\"request_key\" value=\"([a-f0-9]{32})\"",sys.stdin.read()).group(1))')
payload="request_key=$key&title=Reported%20%3Cscript%3EtitleProbe()%3C%2Fscript%3E&severity=HIGH&report=Claimed%20access%20%3Cscript%3EreportProbe()%3C%2Fscript%3E"
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "$payload" "$base/incident-new.php")" = 403 ]
[ "$(post_status "$payload&author_id=1")" = 422 ]
[ "$(post_status "$payload&is_simulated=1")" = 422 ]
[ "$(post_status "$payload&assigned_to=1")" = 422 ]
[ "$(post_status "$payload&risk_score=99")" = 422 ]
[ "$(post_status 'title[]=bad&severity=HIGH&report=Reason&request_key=bad')" = 422 ]
invalid="request_key=$key&title=%3Cscript%3EretainedProbe()%3C%2Fscript%3E&severity=BAD&report=Retained%20report"
page=$(curl --silent --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$invalid" "$base/incident-new.php")
printf '%s' "$page" | grep -q '&lt;script&gt;retainedProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q "name=\"request_key\" value=\"$key\""
printf '%s' "$page" | grep -q 'Retained report'
if printf '%s' "$page" | grep -q '<script>retainedProbe()';then exit 1;fi
[ "$(post_status "$payload")" = 303 ]
[ "$(post_status "$payload")" = 303 ]
[ "$(post_status "$payload&title=Different%20report")" = 409 ]
id=$(docker compose exec -T web php -r 'require "includes/db.php";$s=$pdo->prepare("SELECT incident_id FROM manual_case_requests WHERE user_id=? AND request_key=?");$s->execute([(int)$argv[1],$argv[2]]);$rows=$s->fetchAll(PDO::FETCH_COLUMN);if(count($rows)!==1||!$rows[0])exit(1);echo $rows[0];' "$analyst" "$key")
page=$(get "incidents.php?id=$id")
printf '%s' "$page" | grep -q 'This submission already created a case'
printf '%s' "$page" | grep -q '&lt;script&gt;titleProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q '&lt;script&gt;reportProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q 'No sensor evidence was attached at creation'
if printf '%s' "$page" | grep -Eq '<script>(title|report)Probe';then exit 1;fi
docker compose exec -T web php -r 'require "includes/db.php";$id=(int)$argv[1];$s=$pdo->prepare("SELECT COUNT(*) FROM case_notes WHERE incident_id=? AND author_id=?");$s->execute([$id,(int)$argv[2]]);if((int)$s->fetchColumn()!==1)exit(1);foreach(["incident_alerts","playbook_runs","response_actions","notifications"] as $t){$s=$pdo->prepare("SELECT COUNT(*) FROM $t WHERE incident_id=?");$s->execute([$id]);if((int)$s->fetchColumn()!==0)exit(1);}' "$id" "$analyst"
set_session analyst "$analyst"
page=$(get 'incidents.php');printf '%s' "$page" | grep -q 'href="incident-new.php"'
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-new.php")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
[ "$(curl --silent --request PUT --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-new.php")" = 405 ]
docker compose exec -T web php -r 'require "includes/db.php";$pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute(["user",(int)$argv[1]]);' "$analyst"
[ "$(post_status "$payload")" = 403 ]
set_session user "$reader"
page=$(get 'incidents.php');if printf '%s' "$page" | grep -q 'href="incident-new.php"';then exit 1;fi
echo 'PASS: manual intake HTTP role checks, CSRF, retry identity, conflict, form retention, escaped reports, navigation and absence of fabricated evidence'
