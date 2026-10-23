#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cisoc$(date +%s)$$"
base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/soc.php")" = 302 ]
log_id=$(docker compose exec -T web php -r '
require "includes/db.php";require "includes/siem/EventEvidenceRepository.php";
$repo=new EventEvidenceRepository($pdo);$time=$pdo->query("SELECT DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 HOUR)")->fetchColumn();
$real=0;foreach([false,true] as $sim){$message=$sim?"SOC_SIMULATION_HIDDEN":"<script>socProbe()</script>";
$pdo->prepare("INSERT INTO logs (source_ip,severity,message) VALUES (?,\x27HIGH\x27,?)")->execute(["192.0.2.19",$message]);$id=(int)$pdo->lastInsertId();
$repo->append($id,["source"=>"<b>claimed source</b>","source_type"=>"sensor","source_event_id"=>(string)$id,"is_simulated"=>$sim,"event_timestamp"=>$time,"received_at"=>$time],[],hash("sha256","soc-http-".$id),"ci-overview",null);if(!$sim)$real=$id;}
$pdo->exec("INSERT INTO logs (message,severity) VALUES (\x27SOC_LEGACY_HIDDEN\x27,\x27CRITICAL\x27)");echo $real;
')
docker compose exec -T -u www-data web php -r '
session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="soc-reader";$_SESSION["role"]="user";session_write_close();
' "$session_id"
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/soc.php")
printf '%s' "$page" | grep -q '&lt;script&gt;socProbe()&lt;/script&gt;'
printf '%s' "$page" | grep -q '&lt;b&gt;claimed source&lt;/b&gt;'
printf '%s' "$page" | grep -q "events.php?kind=observed&amp;log_id=$log_id"
printf '%s' "$page" | grep -q 'incidents.php?kind=observed&amp;lifecycle=active&amp;owner=unassigned'
printf '%s' "$page" | grep -q 'External intelligence inventory'
if printf '%s' "$page" | grep -Eq '<script>socProbe|SOC_SIMULATION_HIDDEN|SOC_LEGACY_HIDDEN|Source separation is planned|Some sections are unavailable';then echo 'Incorrect overview rendering';exit 1;fi
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/soc.php")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
echo 'PASS: SOC overview login, reader access, escaping, evidence links, workload links, simulation/legacy exclusion and no-store'
