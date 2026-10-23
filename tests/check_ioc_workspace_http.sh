#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="ciioc$(date +%s)$$";csrf_token='ci-ioc-token';base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-iocs.php?id=1")" = 302 ] || exit 1
ids=$(docker compose exec -T web php -r '
 require "includes/db.php";require "includes/soar/IncidentManager.php";require "includes/soar/IocRepository.php";
 $name="ioc_http_".bin2hex(random_bytes(6));$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","analyst"]);$uid=(int)$pdo->lastInsertId();
 $manager=new IncidentManager($pdo);$case=$manager->createIncident(["title"=>"Case <script>probe()</script>"]);$other=$manager->createIncident(["title"=>"Simulated IOC case","is_simulated"=>true]);
 $repo=new IocRepository($pdo);$ioc=$repo->upsertIoc(["ioc_type"=>"URL","ioc_value"=>"https://ioc-fixture.test/?q=<script>probe()</script>"]);$repo->attachToIncident($case["id"],$ioc);
 $repo->saveEnrichmentResult($ioc,"<script>probe()</script>","SUCCESS",["token"=>"RAW_SECRET"],["reputation"=>90,"confidence"=>80,"summary"=>["token"=>"SUMMARY_SECRET"]],date("Y-m-d H:i:s",time()+3600));
 echo $uid." ".$case["id"]." ".$other["id"]." ".$ioc;
')
set -- $ids
user_id="$1";incident_id="$2";other_id="$3";ioc_id="$4"
set_role(){ docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="session-alias";$_SESSION["user_id"]=(int)$argv[2];$_SESSION["role"]=$argv[3];$_SESSION["csrf_token"]=$argv[4];session_write_close();
 ' "$session_id" "$user_id" "$1" "$csrf_token"; }
post_status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$1" "$base/incident-iocs.php"; }
set_role user
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-iocs.php?id=$incident_id&ioc_id=$ioc_id")
printf '%s' "$page" | grep -q 'Malicious report'
printf '%s' "$page" | grep -q '&lt;script&gt;probe()&lt;/script&gt;'
if printf '%s' "$page" | grep -Eq '<script>probe|RAW_SECRET|SUMMARY_SECRET|<button type="submit">Discover saved';then echo 'Unsafe reader page';exit 1;fi
[ "$(post_status "id=$incident_id")" = 403 ] || { echo 'Tier 1 discovery accepted';exit 1; }
set_role analyst
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "id=$incident_id" "$base/incident-iocs.php")
[ "$status" = 403 ] || { echo 'Missing CSRF accepted';exit 1; }
[ "$(post_status "id=$incident_id&enrich_now=1")" = 422 ] || { echo 'Provider override accepted';exit 1; }
[ "$(post_status "id=$incident_id")" = 303 ] || { echo 'Local discovery failed';exit 1; }
[ "$(post_status "id=$incident_id")" = 303 ] || { echo 'Retry failed';exit 1; }
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-iocs.php?id=$incident_id")
printf '%s' "$page" | grep -q 'added 0 new case links'
[ "$(post_status "id=$other_id")" = 409 ] || { echo 'Simulation mutation accepted';exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-iocs.php?id=$other_id&ioc_id=$ioc_id")
[ "$status" = 404 ] || { echo 'Cross-case indicator accepted';exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-iocs.php?id=$incident_id&type=INVALID")
[ "$status" = 422 ] || { echo 'Invalid type accepted';exit 1; }
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-iocs.php?id=$other_id")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
docker compose exec -T web php -r '
 require "includes/db.php";$s=$pdo->prepare("SELECT COUNT(*) FROM incident_iocs WHERE incident_id=?");$s->execute([(int)$argv[1]]);if((int)$s->fetchColumn()!==1)exit(1);
 $s=$pdo->prepare("SELECT COUNT(*) FROM enrichment_results WHERE ioc_id=?");$s->execute([(int)$argv[2]]);if((int)$s->fetchColumn()!==1)exit(1);
 $pdo->prepare("UPDATE users SET role=? WHERE id=?")->execute(["user",(int)$argv[3]]);
' "$incident_id" "$ioc_id" "$user_id"
[ "$(post_status "id=$incident_id")" = 403 ] || { echo 'Revoked database role accepted';exit 1; }
echo 'PASS: IOC HTTP reader access, escaping, payload omission, CSRF, role checks, local-only action, retry, simulation and case scoping'
