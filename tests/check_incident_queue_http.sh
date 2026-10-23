#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="ciqueue$(date +%s)$$"
base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incidents.php?q=test")" = 302 ]
fixture=$(docker compose exec -T web php -r '
require "includes/db.php";require "includes/soar/IncidentRepository.php";
$name="queue-http-".bin2hex(random_bytes(6));
$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","user"]);$user=(int)$pdo->lastInsertId();
$r=new IncidentRepository($pdo);
for($n=0;$n<27;$n++){$id=$r->create(["incident_number"=>$name."-".$n,"title"=>$name." <script>queueProbe()</script>","is_simulated"=>true,"assigned_to"=>$user]);}
echo $name." ".$user;
')
set -- $fixture
name="$1"; user_id="$2"
docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="queue-reader";$_SESSION["role"]="user";$_SESSION["user_id"]=(int)$argv[2];session_write_close();
' "$session_id" "$user_id"
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php?$1"; }
page=$(get "q=$name&kind=simulated&owner=mine&lifecycle=active&sort=oldest&page=999999")
printf '%s' "$page" | grep -q 'Page 2 of 2'
printf '%s' "$page" | grep -q '&lt;script&gt;queueProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q "q=$name&amp;kind=simulated"
printf '%s' "$page" | grep -q 'owner=mine.*sort=oldest.*page=1'
if printf '%s' "$page" | grep -q '<script>queueProbe()'; then echo 'Unsafe title rendering';exit 1;fi
page=$(get "q=$name")
printf '%s' "$page" | grep -q 'No incidents match these filters.'
page=$(get "q=$name&kind=simulated&owner=unassigned")
printf '%s' "$page" | grep -q 'No incidents match these filters.'
page=$(get "q=$name&kind=simulated&mine=1")
printf '%s' "$page" | grep -q 'Page 1 of 2'
page=$(get 'q=%22%3E%3Cscript%3EsearchProbe()%3C%2Fscript%3E')
printf '%s' "$page" | grep -q '&quot;&gt;&lt;script&gt;searchProbe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>searchProbe()';then exit 1;fi
status=$(curl --silent --globoff --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php?q[]=bad")
[ "$status" = 422 ]
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incidents.php")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
echo 'PASS: queue HTTP reader access, search escaping, simulation exclusion, ownership, bookmarked mine, page clamping and filter-preserving links'
