#!/bin/sh
# Disposable Compose CI only.
set -eu
session_id="cipreview$(date +%s)$$";csrf_token='ci-preview-token';base='http://localhost:8080'
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/incident-playbooks.php?id=1")" = 302 ] || exit 1
ids=$(docker compose exec -T web php -r '
 require "includes/db.php";require "includes/soar/IncidentManager.php";require "includes/soar/playbooks/PlaybookRepository.php";
 $name="preview_http_".bin2hex(random_bytes(6));$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")->execute([$name,"not-a-login-hash","user"]);$uid=(int)$pdo->lastInsertId();
 $manager=new IncidentManager($pdo);$case=$manager->createIncident(["title"=>"Case <script>probe()</script>"]);$other=$manager->createIncident(["title"=>"Other preview case","is_simulated"=>true]);
 $repo=new PlaybookRepository($pdo);$pb=$repo->createPlaybook(["playbook_name"=>$name,"display_name"=>"Preview <script>probe()</script>","category"=>"INVESTIGATION"],$uid);
 $repo->createStep($pb,["step_order"=>1,"step_name"=>"Approval","action_type"=>"REQUEST_APPROVAL","action_parameters"=>[]]);
 $repo->createStep($pb,["step_order"=>2,"step_name"=>"Note","action_type"=>"ADD_INCIDENT_NOTE","action_parameters"=>["note"=>"<script>probe()</script>"]]);
 echo $uid." ".$case["id"]." ".$other["id"]." ".$pb;
')
set -- $ids
user_id="$1";incident_id="$2";other_id="$3";playbook_id="$4"
set_user(){ docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="session-alias";$_SESSION["user_id"]=(int)$argv[2];$_SESSION["role"]="user";$_SESSION["csrf_token"]=$argv[3];session_write_close();
 ' "$session_id" "$1" "$csrf_token"; }
set_user "$user_id"
post_status(){ curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H "X-CSRF-Token: $csrf_token" --data "$1" "$base/incident-playbooks.php"; }
key='00000000000000000000000000000001'
payload="id=$incident_id&playbook_id=$playbook_id&version=1&request_key=$key"
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-playbooks.php?id=$incident_id&playbook_id=$playbook_id")
printf '%s' "$page" | grep -q 'Run saved preview'
printf '%s' "$page" | grep -q '&lt;script&gt;probe()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>probe()</script>';then echo 'Unescaped definition';exit 1;fi
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" --data "$payload" "$base/incident-playbooks.php")
[ "$status" = 403 ] || { echo 'Missing CSRF accepted';exit 1; }
[ "$(post_status "$payload&mode=MANUAL")" = 422 ] || { echo 'Execution mode override accepted';exit 1; }
[ "$(post_status "id=$incident_id&playbook_id=$playbook_id&version=99&request_key=$key")" = 409 ] || { echo 'Stale version accepted';exit 1; }
[ "$(post_status "$payload")" = 303 ] || { echo 'Named Tier 1 preview failed';exit 1; }
[ "$(post_status "$payload")" = 303 ] || { echo 'Replay failed';exit 1; }
run_id=$(docker compose exec -T web php -r '
 require "includes/db.php";$s=$pdo->prepare("SELECT id,execution_context,status FROM playbook_runs WHERE incident_id=?");$s->execute([(int)$argv[1]]);$r=$s->fetchAll();if(count($r)!==1||$r[0]["status"]!=="COMPLETED"||json_decode($r[0]["execution_context"],true)["mode"]!=="DRY_RUN")exit(1);echo $r[0]["id"];
' "$incident_id")
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-playbooks.php?id=$incident_id&run_id=$run_id")
printf '%s' "$page" | grep -q 'COMPLETED'
printf '%s' "$page" | grep -q 'dry-run does not create an approval request'
printf '%s' "$page" | grep -q 'Definition saved with this preview'
if printf '%s' "$page" | grep -q '<script>probe()</script>';then echo 'Unescaped result';exit 1;fi
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-playbooks.php?id=$other_id&run_id=$run_id")
[ "$status" = 404 ] || { echo 'Cross-case run accepted';exit 1; }
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/incident-playbooks.php?id=$other_id")
printf '%s' "$page" | grep -q 'SIMULATED TEST DATA'
docker compose exec -T web php -r '
 require "includes/db.php";foreach(["approval_requests","case_notes","notifications","evidence","response_actions"] as $t){$s=$pdo->prepare("SELECT COUNT(*) FROM $t WHERE incident_id=?");$s->execute([(int)$argv[1]]);if((int)$s->fetchColumn()!==0)exit(1);}
' "$incident_id"
set_user 2147483647
[ "$(post_status "$payload")" = 403 ] || { echo 'Unverified database user previewed';exit 1; }
echo 'PASS: playbook HTTP login, named Tier 1 preview, CSRF, forced mode, version checks, retry identity, scoped history, labels and escaped rendering'
