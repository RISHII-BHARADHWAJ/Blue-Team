#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cisources$(date +%s)$$"
base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/sources.php")" = 302 ]
fixture=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r '
require "tests/source_activity_fixtures.php";
$name="sources-http-".bin2hex(random_bytes(5));
$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","user"]);$user=(int)$pdo->lastInsertId();
$source=$name."<script>sourceProbe()</script>";
for($n=0;$n<27;$n++) sourceFixture($pdo,$source,sprintf("actor-%02d",$n)."<script>actorProbe()</script>",-60,false,"REAL_HTTP_EVIDENCE");
sourceFixture($pdo,$source,"simulated-actor",-60,true,"SIMULATED_HTTP_EVIDENCE");
$longSource=str_repeat("界",80);$longActor=$name.str_repeat("x",210);
$longId=sourceFixture($pdo,$longSource,$longActor,-60,false,"LONG_IDENTITY_EVIDENCE");
sourceFixture($pdo,$longSource,$longActor."X",-60,false,"OTHER_IDENTITY_EVIDENCE");
echo $name." ".$user." ".http_build_query(["kind"=>"observed","source"=>$longSource,"submitted_by"=>$longActor])." ".$longId;
')
set -- $fixture
name="$1"; user_id="$2"; exact_query="$3"; long_id="$4"
docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="source-reader";$_SESSION["role"]="user";$_SESSION["user_id"]=(int)$argv[2];session_write_close();
' "$session_id" "$user_id"
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
# Text matches names as well as submitter; exclude the long-identity fixtures from this page query.
page=$(get "sources.php?q=$name%3Cscript&kind=observed&hours=24&activity=recent&sort=oldest&page=999999")
printf '%s' "$page" | grep -q 'Page 2 of 2'
[ "$(printf '%s' "$page" | grep -o 'data-source-row="1"' | grep -c .)" = 2 ]
printf '%s' "$page" | grep -q '&lt;script&gt;sourceProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q '&lt;script&gt;actorProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q 'kind=observed&amp;hours=24&amp;activity=recent&amp;sort=oldest&amp;page=1'
printf '%s' "$page" | grep -q 'events.php?kind=observed&amp;source=.*&amp;submitted_by=actor-'
if printf '%s' "$page" | grep -Eq '<script>(source|actor)Probe|simulated-actor';then echo 'Unsafe or simulated source rendering';exit 1;fi
page=$(get "sources.php?q=$name%3Cscript&kind=simulated")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q 'simulated-actor'
page=$(get "sources.php?q=$name%3Cscript&activity=quiet")
printf '%s' "$page" | grep -q 'No sources match these filters.'
page=$(get 'sources.php?q=%22%3E%3Cscript%3EqueryProbe()%3C%2Fscript%3E')
printf '%s' "$page" | grep -q '&quot;&gt;&lt;script&gt;queryProbe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>queryProbe()';then exit 1;fi
page=$(get "events.php?$exact_query")
printf '%s' "$page" | grep -q '1 matching submissions'
printf '%s' "$page" | grep -q "Inspect log #$long_id"
printf '%s' "$page" | grep -q 'LONG_IDENTITY_EVIDENCE'
if printf '%s' "$page" | grep -q 'OTHER_IDENTITY_EVIDENCE';then echo 'Submitter filter broadened';exit 1;fi
printf '%s' "$page" | grep -q 'Authenticated submitter (exact)'
printf '%s' "$page" | grep -q 'href="sources.php"'
page=$(get "sources.php?q=${name}xxxxxxxxxxxxxxxxxxxx")
printf '%s' "$page" | grep -Fq "events.php?$(printf '%s' "$exact_query" | sed 's/\&/\&amp;/g')"
for query in 'q[]=bad' 'kind=all' 'hours=0' 'sort=DROP' 'activity=healthy'; do
  [ "$(curl --globoff --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/sources.php?$query")" = 422 ]
done
[ "$(curl --globoff --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/events.php?submitted_by[]=bad")" = 400 ]
[ "$(curl --silent --request POST --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/sources.php")" = 405 ]
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/sources.php")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
page=$(get 'soc.php')
printf '%s' "$page" | grep -q 'href="sources.php"'
echo 'PASS: source activity reader access, pagination, escaped identities, simulation separation, full identity drill-down, filters and read-only method guards'
