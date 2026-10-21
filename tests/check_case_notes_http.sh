#!/bin/sh
# Run against disposable CI Compose only; fixture credentials cannot log in.
set -eu
session_id="cinotes$(date +%s)$$"
csrf_token="ci-case-note-token"
cleanup() {
 docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION"); session_id($argv[1]); session_start(); session_destroy();
 ' "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT
ids=$(docker compose exec -T web php -r '
 require "includes/db.php"; require "includes/soar/IncidentManager.php";
 $username="notes-http-".bin2hex(random_bytes(6));
 $pdo->prepare("INSERT INTO users (username,password,role) VALUES (?, ?, ?)")->execute([$username, password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT), "user"]);
 $userId=(int)$pdo->lastInsertId();
 $i=(new IncidentManager($pdo))->createIncident(["title"=>"Notes HTTP fixture", "severity"=>"INFO"]);
 echo $userId." ".$i["id"];
')
set -- $ids
user_id="$1"
incident_id="$2"
docker compose exec -T -u www-data web php -r '
 session_name("CYBERTECH_SECURE_SESSION"); session_id($argv[1]); session_start();
 $_SESSION["analyst"]="ci-note-session"; $_SESSION["user_id"]=(int)$argv[2];
 $_SESSION["role"]="user"; $_SESSION["csrf_token"]=$argv[3]; session_write_close();
' "$session_id" "$user_id" "$csrf_token"
endpoint="http://localhost:8080/api/v1/case_notes.php"
payload="{\"incident_id\":$incident_id,\"note\":\"<script>noteTest()</script>\",\"author_id\":999999}"
status=$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Content-Type: application/json' --data "$payload" "$endpoint")
[ "$status" = 401 ] || { echo 'Anonymous note write accepted' >&2; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H 'Content-Type: application/json' --data "$payload" "$endpoint")
[ "$status" = 403 ] || { echo 'Missing CSRF was accepted' >&2; exit 1; }
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf_token" --data "$payload" "$endpoint")
[ "$status" = 201 ] || { echo "Tier 1 note creation failed: $status" >&2; exit 1; }
docker compose exec -T web php -r '
 require "includes/db.php";
 $s=$pdo->prepare("SELECT author_id FROM case_notes WHERE incident_id=?"); $s->execute([(int)$argv[1]]);
 if ((int)$s->fetchColumn() !== (int)$argv[2]) exit(1);
' "$incident_id" "$user_id"
page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "http://localhost:8080/incidents.php?id=$incident_id")
printf '%s' "$page" | grep -q 'id="case-note-form"'
printf '%s' "$page" | grep -q '&lt;script&gt;noteTest()&lt;/script&gt;'
if printf '%s' "$page" | grep -q '<script>noteTest()</script>'; then echo 'Unsafe note rendering' >&2; exit 1; fi
if printf '%s' "$page" | grep -q 'id="triage-form"'; then echo 'Tier 1 note permission exposed triage' >&2; exit 1; fi
echo 'PASS: case note authentication, CSRF, Tier 1 access, author spoof rejection and escaped rendering'
