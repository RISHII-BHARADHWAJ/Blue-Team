#!/bin/sh
# HTTP integration regression: Tier 1 must not mutate incidents, even with a valid CSRF token.
# Run only on the disposable GitHub Actions Docker Compose stack.
set -eu

session_id="ciincident$(date +%s)$$"
csrf_token="ci-rbac-test-token"
api_url="http://localhost:8080/api/v1/incidents_detail.php"

set_session() {
  test_role="$1"
  docker compose exec -T -u www-data web php -r '
    session_name("CYBERTECH_SECURE_SESSION");
    session_id($argv[1]);
    session_start();
    $_SESSION["analyst"] = "ci_fixture_analyst";
    $_SESSION["role"] = $argv[2];
    $_SESSION["csrf_token"] = $argv[3];
    session_write_close();
  ' "$session_id" "$test_role" "$csrf_token"
}

request_status() {
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --cookie "CYBERTECH_SECURE_SESSION=$session_id" \
    --header "X-CSRF-Token: $csrf_token" \
    --data-urlencode "id=999999" \
    --data-urlencode "action=$1" \
    --data-urlencode "new_status=OPEN" \
    --data-urlencode "analyst_id=1" \
    --data-urlencode "log_id=1" \
    "$api_url"
}

cleanup() {
  docker compose exec -T -u www-data web php -r '
    session_name("CYBERTECH_SECURE_SESSION");
    session_id($argv[1]);
    session_start();
    session_destroy();
  ' "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Seed one ordinary incident in the disposable CI database for UI authorization.
fixture_id=$(docker compose exec -T web php -r '
  require "includes/db.php";
  require "includes/soar/IncidentManager.php";
  $created = (new IncidentManager($pdo))->createIncident([
      "title" => "CI analyst triage UI fixture",
      "severity" => "MEDIUM",
  ]);
  echo (int)$created["id"];
')
case "$fixture_id" in
  ''|*[!0-9]*) echo "Failed to create disposable incident UI fixture" >&2; exit 1 ;;
esac
ui_url="http://localhost:8080/incidents.php?id=$fixture_id"

set_session "user"
tier1_page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$ui_url")
echo "$tier1_page" | grep -q 'Read-only access: Tier 2 or higher'
if echo "$tier1_page" | grep -q 'id="triage-form"'; then
  echo "Tier 1 incident UI exposed mutation controls" >&2
  exit 1
fi
echo "PASS: Tier 1 incident detail is read-only"

for action in change_status assign attach_alert; do
  status=$(request_status "$action")
  if [ "$status" != "403" ]; then
    echo "Tier 1 unexpectedly allowed $action (HTTP $status)" >&2
    exit 1
  fi
  echo "PASS: Tier 1 denied $action"
done

# Tier 2 is allowed through the capability gate. The deliberately nonexistent
# incident then returns 404 without creating or changing any actual record.
set_session "analyst"
tier2_page=$(curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$ui_url")
echo "$tier2_page" | grep -q 'id="triage-form"'
echo "$tier2_page" | grep -q 'value="OPEN"'
echo "PASS: Tier 2 incident UI exposes valid NEW to OPEN transition"
for action in change_status assign attach_alert; do
  status=$(request_status "$action")
  if [ "$status" != "404" ]; then
    echo "Tier 2 did not reach incident existence validation for $action (HTTP $status)" >&2
    exit 1
  fi
  echo "PASS: Tier 2 action $action reached safe 404 for missing incident"
done

echo "Incident API RBAC checks passed"
