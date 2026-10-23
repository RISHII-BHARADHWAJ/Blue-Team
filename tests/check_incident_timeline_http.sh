#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="citimeline$(date +%s)$$"
base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-timeline.php?id=1")" = 302 ]
fixture=$(docker compose exec -T web php -r '
require "includes/db.php";require "includes/soar/IncidentRepository.php";require "includes/soar/IncidentTimeline.php";
$name="timeline-http-".bin2hex(random_bytes(6));
$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","user"]);$user=(int)$pdo->lastInsertId();
$r=new IncidentRepository($pdo);$t=new IncidentTimeline($pdo);
$case=$r->create(["incident_number"=>$name,"title"=>"<script>caseProbe()</script>","is_simulated"=>true]);
$other=$r->create(["incident_number"=>$name."-other","title"=>$name]);
for($n=0;$n<27;$n++){$t->addEvent($case,"NOTE_ADDED","ANALYST","<script>actorProbe()</script>","entry$n <script>timelineProbe()</script>",["hidden"=>"DETAIL_ONLY_SENTINEL"]);}
$t->addEvent($other,"NOTE_ADDED","ANALYST","other","OTHER_CASE_SENTINEL");
$pdo->prepare("UPDATE incident_timeline SET created_at=? WHERE incident_id=?")->execute(["2020-01-01 00:00:00",$case]);
echo $case." ".$other." ".$user;
')
set -- $fixture
case_id="$1"; other_id="$2"; user_id="$3"
docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="timeline-reader";$_SESSION["role"]="user";$_SESSION["user_id"]=(int)$argv[2];session_write_close();
' "$session_id" "$user_id"
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-timeline.php?$1"; }
page=$(get "id=$case_id&q=entry&event_type=NOTE_ADDED&actor_type=ANALYST&sort=oldest&page=999999")
printf '%s' "$page" | grep -q 'Page 2 of 2'
[ "$(printf '%s' "$page" | grep -c 'data-timeline-id=')" = 2 ]
printf '%s' "$page" | grep -q 'entry25 &lt;script&gt;timelineProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q '&lt;script&gt;actorProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q '&lt;script&gt;caseProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q 'SIMULATED CASE'
printf '%s' "$page" | grep -q "id=$case_id&amp;q=entry&amp;event_type=NOTE_ADDED&amp;actor_type=ANALYST&amp;sort=oldest&amp;page=1"
if printf '%s' "$page" | grep -Eq '<script>(timeline|actor|case)Probe|DETAIL_ONLY_SENTINEL|OTHER_CASE_SENTINEL'; then echo 'Unsafe or cross-case rendering';exit 1;fi
page=$(get "id=$case_id")
[ "$(printf '%s' "$page" | grep -c 'data-timeline-id=')" = 25 ]
printf '%s' "$page" | grep -q 'entry26 &lt;script&gt;'
page=$(get "id=$case_id&actor_type=SYSTEM")
printf '%s' "$page" | grep -q 'No timeline entries match these filters.'
page=$(get "id=$case_id&q=%22%3E%3Cscript%3EsearchProbe()%3C%2Fscript%3E")
printf '%s' "$page" | grep -q '&quot;&gt;&lt;script&gt;searchProbe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>searchProbe()';then exit 1;fi
page=$(get "id=$other_id")
printf '%s' "$page" | grep -q 'OTHER_CASE_SENTINEL'
if printf '%s' "$page" | grep -q 'SIMULATED CASE';then exit 1;fi
for query in "id=$case_id&q[]=bad" "id=$case_id&sort=invalid" 'id[]=1' 'id=0'; do
  [ "$(curl --globoff --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-timeline.php?$query")" = 422 ]
done
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-timeline.php?id=9223372036854775807")" = 404 ]
[ "$(curl --silent --request POST --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-timeline.php?id=$case_id")" = 405 ]
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-timeline.php?id=$case_id")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php?id=$case_id")
printf '%s' "$page" | grep -q "incident-timeline.php?id=$case_id"
printf '%s' "$page" | grep -q 'Up to 20 latest entries, newest first (UTC)'
[ "$(printf '%s' "$page" | grep -o '<div class="event"><strong>NOTE_ADDED' | grep -c .)" = 20 ]
if printf '%s' "$page" | grep -q 'entry0 &lt;script&gt;';then echo 'Case preview was not bounded';exit 1;fi
echo 'PASS: timeline reader access, pagination, preserved filters, case isolation, simulation labels, escaping, method guards and bounded case preview'
