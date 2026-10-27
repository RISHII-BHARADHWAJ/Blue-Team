#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cirisk$(date +%s)$$"
csrf_token='ci-risk-token'
base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-risk.php?id=1")" = 302 ] || exit 1
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/api/v1/incidents_risk.php?id=1")" = 401 ] || exit 1
ids=$(docker compose exec -T web php -r '
 require "includes/db.php";require "includes/soar/IncidentManager.php";
 $name="risk-http-".bin2hex(random_bytes(5))."<b>probe</b>";
 $pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","admin"]);$uid=(int)$pdo->lastInsertId();
 $manager=new IncidentManager($pdo);$case=$manager->createIncident(["title"=>"Risk <script>probe()</script>","severity"=>"HIGH","is_simulated"=>true]);
 $other=$manager->createIncident(["title"=>"Other risk case"]);echo $uid." ".$case["id"]." ".$other["id"];
')
set -- $ids
user_id="$1";incident_id="$2";other_id="$3"
# The real database role is authoritative; change the disposable actor too.
set_role(){
 docker compose exec -T -u www-data web php -r '
 require "includes/db.php"; $pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute([$argv[3],(int)$argv[2]]);
 session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="session-alias";$_SESSION["user_id"]=(int)$argv[2];$_SESSION["role"]=$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();
 ' "$session_id" "$user_id" "$1" "$csrf_token"
}
post_status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" -H 'Content-Type: application/json' --data "$1" "$base/api/v1/incidents_risk.php"; }
set_role user
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-risk.php?id=$incident_id")
printf '%s' "$page" | grep -q 'No saved risk assessment'
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
printf '%s' "$page" | grep -q '&lt;script&gt;probe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>probe()</script>';then echo 'Unescaped title';exit 1;fi
if printf '%s' "$page" | grep -q 'id="recalculate"';then echo 'Reader got recalculate button';exit 1;fi
response=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/incidents_risk.php?id=$incident_id")
printf '%s' "$response" | docker compose exec -T web php -r '$r=json_decode(stream_get_contents(STDIN),true);if($r["data"]["latest"]!==null || $r["data"]["history"]!==[])exit(1);'
docker compose exec -T web php -r '
 require "includes/db.php";$s=$pdo->prepare("SELECT COUNT(*) FROM risk_assessments WHERE incident_id=?");$s->execute([(int)$argv[1]]);if((int)$s->fetchColumn()!==0)exit(1);
 $s=$pdo->prepare("SELECT priority FROM incidents WHERE id=?");$s->execute([(int)$argv[1]]);if($s->fetchColumn()!=="P2")exit(1);
' "$incident_id"
[ "$(post_status "{\"incident_id\":$incident_id}")" = 403 ] || { echo 'Reader recalculated';exit 1; }
set_role admin
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H 'Content-Type: application/json' --data "{\"incident_id\":$incident_id}" "$base/api/v1/incidents_risk.php")
[ "$status" = 403 ] || { echo 'Missing CSRF accepted';exit 1; }
[ "$(post_status '{broken')" = 400 ] || exit 1
[ "$(post_status '{"incident_id":-1}')" = 400 ] || exit 1
[ "$(post_status "{\"incident_id\":$incident_id,\"risk_score\":null}")" = 422 ] || { echo 'Score override accepted';exit 1; }
[ "$(post_status "{\"incident_id\":$incident_id,\"asset_metadata\":{\"criticality\":\"CRITICAL\"}}")" = 422 ] || { echo 'Client asset context accepted';exit 1; }
[ "$(post_status "{\"incident_id\":$incident_id}")" = 200 ] || { echo 'Admin recalculation failed';exit 1; }
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-risk.php?id=$incident_id")
printf '%s' "$page" | grep -q 'Where the points came from'
printf '%s' "$page" | grep -q 'Policy v1.1'
printf '%s' "$page" | grep -q '&lt;b&gt;probe&lt;/b&gt;'
assessment_id=$(docker compose exec -T web php -r 'require "includes/db.php";$s=$pdo->prepare("SELECT id FROM risk_assessments WHERE incident_id=? ORDER BY id DESC LIMIT 1");$s->execute([(int)$argv[1]]);echo $s->fetchColumn();' "$incident_id")
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-risk.php?id=$other_id&assessment_id=$assessment_id")
[ "$status" = 404 ] || { echo 'Cross-case assessment exposed';exit 1; }
docker compose exec -T web php -r 'require "includes/db.php";$pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute(["user",(int)$argv[1]]);' "$user_id"
[ "$(post_status "{\"incident_id\":$incident_id}")" = 403 ] || { echo 'Revoked database role recalculated';exit 1; }
echo 'PASS: risk HTTP read-only GET, role/CSRF enforcement, explicit recalculation, input validation, simulation labels, historical scoping and safe rendering'
