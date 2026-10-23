#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cireport$(date +%s)$$";base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-report.php?id=1")" = 302 ] || exit 1
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-report.php?id=1&format=json")" = 401 ] || exit 1
ids=$(docker compose exec -T web php -r '
 require "includes/db.php";require "includes/soar/IncidentManager.php";
 $name="report_http_".bin2hex(random_bytes(6));$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","user"]);$uid=(int)$pdo->lastInsertId();
 $manager=new IncidentManager($pdo);$case=$manager->createIncident(["title"=>"Case <script>probe()</script>","is_simulated"=>true]);$other=$manager->createIncident(["title"=>"OTHER_CASE_SECRET"]);
 $stmt=$pdo->prepare("INSERT INTO case_notes (incident_id,author_id,note_text) VALUES (?,?,?)");
 for($i=0;$i<101;$i++)$stmt->execute([$case["id"],$uid,"Note </script><script>probe()</script> ".$i]);
 $stmt->execute([$other["id"],$uid,"OTHER_NOTE_SECRET"]);
 echo $uid." ".$case["id"];
')
set -- $ids
user_id="$1";incident_id="$2"
docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="report-reader";$_SESSION["user_id"]=(int)$argv[2];$_SESSION["role"]="user";session_write_close();
' "$session_id" "$user_id"
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-report.php?id=$incident_id")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q 'PARTIAL REPORT'
printf '%s' "$page" | grep -q '100 of 101 records'
printf '%s' "$page" | grep -q '&lt;script&gt;probe()&lt;/script&gt;'
printf '%s' "$page" | grep -q 'No saved risk assessment'
if printf '%s' "$page" | grep -Eq '<script>probe|OTHER_CASE_SECRET|OTHER_NOTE_SECRET';then echo 'Unsafe report HTML';exit 1;fi
printf '%s' "$page" | docker compose exec -T web php -r '
 $html=stream_get_contents(STDIN);if(!preg_match("~<script type=\"application/json\" id=\"report-snapshot\">(.*?)</script>~s",$html,$m))exit(1);
 $r=json_decode($m[1],true,512,JSON_THROW_ON_ERROR);if($r["schema_version"]!=="threatpulse.incident-report.v1"||!$r["partial"]||$r["sections"]["notes"]["included"]!==100||!str_contains($r["sections"]["notes"]["rows"][0]["note_text"],"<script>probe()</script>"))exit(1);
'
response=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-report.php?id=$incident_id&format=json")
printf '%s' "$response" | docker compose exec -T web php -r '
 $r=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);if(!$r["incident"]["is_simulated"]||$r["sections"]["notes"]["total"]!==101||$r["latest_risk_assessment"]!==null)exit(1);
'
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-report.php?id=$incident_id&format=json")
printf '%s' "$headers" | grep -qi 'Content-Type: application/json'
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
printf '%s' "$headers" | grep -qi 'Content-Disposition: attachment; filename="threatpulse-incident-'
status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-report.php?$1"; }
[ "$(status 'id=-1&format=json')" = 422 ] || exit 1
[ "$(status "id=$incident_id&format=csv")" = 422 ] || exit 1
[ "$(status 'id=2147483647&format=json')" = 404 ] || exit 1
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "id=$incident_id" "$base/incident-report.php")" = 405 ] || exit 1
docker compose exec -T web php -r 'require "includes/db.php";$s=$pdo->prepare("SELECT COUNT(*) FROM case_notes WHERE incident_id=?");$s->execute([(int)$argv[1]]);if((int)$s->fetchColumn()!==101)exit(1);' "$incident_id"
echo 'PASS: report HTTP authentication, reader export, JSON headers, escaped HTML and embedded snapshot, partial labels, scope and method validation'
