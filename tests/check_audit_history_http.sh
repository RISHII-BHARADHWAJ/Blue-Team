#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="ciaudit$(date +%s)$$"; base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/audit.php")" = 302 ]
fixture=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r '
require "tests/audit_history_fixtures.php";
$name="audit-http-".bin2hex(random_bytes(5));$admin=auditUser($pdo,$name."-admin","admin");$lead=auditUser($pdo,$name."-lead","lead");$reader=auditUser($pdo,$name."-reader","user");$analyst=auditUser($pdo,$name."-analyst","analyst");
$m=new IncidentManager($pdo);$case=$m->createIncident(["title"=>$name]);$sim=$m->createIncident(["title"=>$name,"is_simulated"=>true]);
for($n=0;$n<27;$n++)auditFixture($pdo,$name."<script>actorProbe()</script>","<script>actionProbe()</script>","success",$n%2===0?"incident:".$case["id"]:$case["incident_number"]);
auditFixture($pdo,$name,"token: METADATA_SECRET_SENTINEL","blocked","RAW_TARGET_SECRET_SENTINEL");
auditFixture($pdo,$name,"simulation_review","failure","incident:".$sim["id"]);
echo $name." ".$admin." ".$lead." ".$reader." ".$analyst." ".$case["id"]." ".$sim["id"];
')
set -- $fixture
name="$1"; admin="$2"; lead="$3"; reader="$4"; analyst="$5"; case_id="$6"; sim_id="$7"
set_session(){ docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="audit-http-session";$_SESSION["role"]=$argv[2];$_SESSION["user_id"]=(int)$argv[3];session_write_close();
' "$session_id" "$1" "$2"; }
status(){ curl --globoff --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
for id in "$reader" "$analyst";do
  set_session admin "$id"
  [ "$(status "audit.php?q=$name")" = 403 ]
done
for id in 0 2147483647;do
  set_session admin "$id"
  [ "$(status "audit.php?q=$name")" = 302 ]
done
set_session user "$admin"
[ "$(status "audit.php?q=$name")" = 200 ]
set_session lead "$lead"
page=$(get "audit.php?q=$name&result=success&from=2020-01-02&to=2020-01-02&case_id=$case_id&sort=oldest&page=999999")
printf '%s' "$page" | grep -q 'Page 2 of 2'
[ "$(printf '%s' "$page" | grep -o 'data-audit-id=' | grep -c .)" = 2 ]
printf '%s' "$page" | grep -q '&lt;script&gt;actorProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q '&lt;script&gt;actionProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q "result=success&amp;from=2020-01-02&amp;to=2020-01-02&amp;case_id=$case_id&amp;sort=oldest&amp;page=1"
printf '%s' "$page" | grep -q "incidents.php?id=$case_id#details"
if printf '%s' "$page" | grep -Eq '<script>(actor|action)Probe|DETAIL_SECRET_SENTINEL|AGENT_SECRET_SENTINEL';then echo 'Unsafe audit rendering';exit 1;fi
page=$(get "audit.php?q=$name&result=blocked")
printf '%s' "$page" | grep -q 'token: \[REDACTED\]'
printf '%s' "$page" | grep -q 'No direct case reference'
if printf '%s' "$page" | grep -q 'SECRET_SENTINEL';then echo 'Audit payload disclosure';exit 1;fi
page=$(get "audit.php?q=$name&case_id=$sim_id")
printf '%s' "$page" | grep -q 'SIMULATED CASE'
printf '%s' "$page" | grep -q 'badge simulated">SIMULATED'
page=$(get "audit.php?q=$name&from=2021-01-01")
printf '%s' "$page" | grep -q 'No audit records match these filters.'
page=$(get 'audit.php?q=%22%3E%3Cscript%3EqueryProbe()%3C%2Fscript%3E')
printf '%s' "$page" | grep -q '&quot;&gt;&lt;script&gt;queryProbe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>queryProbe()';then exit 1;fi
for query in 'q[]=bad' 'from=2020-02-30' 'from=2020-02-01&to=2020-01-01' 'case_id=-1' 'result=bad' 'sort=DROP';do [ "$(status "audit.php?$query")" = 422 ];done
[ "$(status 'audit.php?case_id=2147483647')" = 404 ]
[ "$(curl --silent --request POST --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/audit.php")" = 405 ]
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/audit.php")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
page=$(get 'soc.php');printf '%s' "$page" | grep -q 'href="audit.php"'
page=$(get "incidents.php?id=$case_id");printf '%s' "$page" | grep -q "audit.php?case_id=$case_id"
# A role downgrade takes effect without refreshing the privileged session.
docker compose exec -T web php -r 'require "includes/db.php";$pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute(["user",(int)$argv[1]]);' "$lead"
[ "$(status "audit.php?q=$name")" = 403 ]
set_session user "$reader"
page=$(get 'soc.php');if printf '%s' "$page" | grep -q 'href="audit.php"';then exit 1;fi
echo 'PASS: audit HTTP current-role access, stale sessions, date filters, pagination, escaping, redaction, payload exclusion, case links, simulation labels and read-only method guards'
