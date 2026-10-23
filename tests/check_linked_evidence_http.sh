#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cilinked$(date +%s)$$"; base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-linked-evidence.php?id=1")" = 302 ]
fixture=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r '
require "tests/event_escalation_fixtures.php";
$name="linked-http-".bin2hex(random_bytes(5));$user=escalationUser($pdo,$name,"user");$r=new IncidentRepository($pdo);
$id=$r->create(["incident_number"=>$name,"title"=>"<script>caseProbe()</script>","status"=>"CLOSED"]);
$other=$r->create(["incident_number"=>$name."-other","title"=>$name]);$sim=$r->create(["incident_number"=>$name."-sim","title"=>$name,"is_simulated"=>true]);
for($n=0;$n<27;$n++){$msg="entry".$n.($n===26?str_repeat("x",510)."TAIL_HTTP_SENTINEL":"");$log=escalationFixture($pdo,$msg);$r->attachAlert($id,$log,"<script>ruleProbe()</script>");}
$legacy=escalationFixture($pdo,"LEGACY_HTTP_ONLY",false,true);$r->attachAlert($id,$legacy,"LEGACY_RULE");
$outside=escalationFixture($pdo,"OTHER_CASE_ONLY");$r->attachAlert($other,$outside,"OTHER_RULE");
$training=escalationFixture($pdo,"TRAINING_ONLY",true);$r->attachAlert($sim,$training,"TRAINING_RULE");
$pdo->prepare("UPDATE logs l JOIN incident_alerts ia ON ia.log_id=l.id SET l.timestamp=? WHERE ia.incident_id=?")->execute(["2020-01-01 00:00:00",$id]);
$pdo->prepare("UPDATE event_evidence e JOIN incident_alerts ia ON ia.log_id=e.log_id SET e.event_timestamp=?, e.source=?, e.submitted_by=? WHERE ia.incident_id=?")->execute(["2020-01-01 00:00:00","<script>sourceProbe()</script>","<script>actorProbe()</script>",$id]);
echo $id." ".$sim." ".$user;
')
set -- $fixture
case_id="$1"; sim_id="$2"; user_id="$3"
docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="linked-reader";$_SESSION["role"]="user";$_SESSION["user_id"]=(int)$argv[2];session_write_close();
' "$session_id" "$user_id"
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
page=$(get "incident-linked-evidence.php?id=$case_id&q=entry&source_ip=192.0.2.89&severity=MEDIUM&provenance=preserved&sort=event_oldest&page=999999")
printf '%s' "$page" | grep -q 'Page 2 of 2'
[ "$(printf '%s' "$page" | grep -o 'data-linked-log=' | grep -c .)" = 2 ]
for value in case source actor rule event; do printf '%s' "$page" | grep -q "&lt;script&gt;${value}Probe()&lt;/script&gt;"; done
printf '%s' "$page" | grep -q 'source_ip=192.0.2.89&amp;severity=MEDIUM&amp;provenance=preserved&amp;sort=event_oldest&amp;page=1'
printf '%s' "$page" | grep -q '\[preview truncated\]'
if printf '%s' "$page" | grep -Eq '<script>(case|source|actor|rule|event)Probe|OTHER_CASE_ONLY|TRAINING_ONLY|TAIL_HTTP_SENTINEL';then echo 'Unsafe, cross-case or unbounded output';exit 1;fi
page=$(get "incident-linked-evidence.php?id=$case_id&provenance=legacy")
printf '%s' "$page" | grep -q 'Legacy log — provenance unavailable'
printf '%s' "$page" | grep -q 'LEGACY_HTTP_ONLY'
if printf '%s' "$page" | grep -q 'Inspect evidence #';then echo 'Legacy log mislabeled as preserved';exit 1;fi
page=$(get "incident-linked-evidence.php?id=$case_id&q=TAIL_HTTP_SENTINEL")
printf '%s' "$page" | grep -q '1 matching links'
page=$(get "incident-linked-evidence.php?id=$case_id&severity=HIGH")
printf '%s' "$page" | grep -q 'No linked evidence matches these filters.'
page=$(get "incident-linked-evidence.php?id=$sim_id")
printf '%s' "$page" | grep -q 'SIMULATED CASE'
printf '%s' "$page" | grep -q 'SIMULATED EVIDENCE'
if printf '%s' "$page" | grep -q 'Find and link additional';then exit 1;fi
page=$(get "incident-linked-evidence.php?id=$case_id&q=%22%3E%3Cscript%3EsearchProbe()%3C%2Fscript%3E")
printf '%s' "$page" | grep -q '&quot;&gt;&lt;script&gt;searchProbe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>searchProbe()';then exit 1;fi
for query in "id=$case_id&q[]=bad" "id=$case_id&sort=bad" 'id[]=1' 'id=0';do
  [ "$(curl --globoff --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-linked-evidence.php?$query")" = 422 ]
done
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-linked-evidence.php?id=9223372036854775807")" = 404 ]
[ "$(curl --silent --request POST --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-linked-evidence.php?id=$case_id")" = 405 ]
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-linked-evidence.php?id=$case_id")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
page=$(get "incidents.php?id=$case_id")
printf '%s' "$page" | grep -q 'Linked SIEM alerts (28)'
printf '%s' "$page" | grep -q "incident-linked-evidence.php?id=$case_id"
[ "$(printf '%s' "$page" | grep -o '· inspect evidence' | grep -c .)" = 20 ]
if printf '%s' "$page" | grep -Eq 'entry0 &lt;script&gt;|TAIL_HTTP_SENTINEL';then echo 'Main case alert preview was not bounded';exit 1;fi
# The legacy API still returns every full message.
json=$(get "api/v1/incidents_detail.php?id=$case_id")
printf '%s' "$json" | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true);if(!$r["success"]||count($r["data"]["alerts"])!==28||!str_contains(json_encode($r),"TAIL_HTTP_SENTINEL"))exit(1);'
echo 'PASS: linked evidence reader access, closed cases, pagination, provenance labels, simulation isolation, escaping, full-message search, bounded case preview and legacy API'
