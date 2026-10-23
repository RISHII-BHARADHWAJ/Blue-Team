#!/bin/sh
set -eu
base='http://localhost:8080'; session_id="ciqueue$(date +%s)$$"
cleanup(){ docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();session_destroy();' "$session_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$base/api/v1/approval_queue.php")" = 401 ]
fixture=$(docker compose exec -T -e SOAR_INTEGRATION_TEST=1 web php -r 'require "tests/approval_queue_fixtures.php";$f=approvalQueueFixture($pdo);echo $f["name"]." ".$f["uid"];')
set -- $fixture; name="$1"; uid="$2"
docker compose exec -T -u www-data web php -r 'session_name("CYBERTECH_SECURE_SESSION");session_id($argv[1]);session_start();$_SESSION["analyst"]="queue-reader";$_SESSION["role"]="user";$_SESSION["user_id"]=(int)$argv[2];session_write_close();' "$session_id" "$uid"
get(){ curl --fail --silent --show-error --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
status(){ curl --globoff --silent --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/$1"; }
get "api/v1/approval_queue.php?q=$name&page=999999" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["success"] and d["pagination"]["total"]==103 and d["pagination"]["page"]==5 and len(d["data"])==3;assert d["metrics"]=={"pending":103,"critical":2,"expiring":2};assert all("action_payload" not in x for x in d["data"])'
get "api/v1/approval_queue.php?q=hiddenneedle%20$name" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["pagination"]["total"]==1 and d["data"][0]["description_truncated"]==1'
get "api/v1/approval_queue.php?q=$name&kind=simulated" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert len(d["data"])==1 and d["data"][0]["is_simulated"]==1 and d["data"][0]["action_name"]=="token: [REDACTED]";assert "QUEUE_PAYLOAD_SECRET" not in str(d)'
get "api/v1/approval_queue.php?q=$name&status=EXPIRED" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["pagination"]["total"]==1 and d["data"][0]["stored_status"]=="PENDING" and d["data"][0]["status"]=="EXPIRED"'
for query in 'q[]=bad' 'page[]=1' 'page=0' 'sort=DROP' 'kind=bad' 'status=bad' 'priority=P9'; do [ "$(status "api/v1/approval_queue.php?$query")" = 422 ]; done
[ "$(curl --silent --request POST --output /dev/null --write-out '%{http_code}' --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/approval_queue.php")" = 405 ]
headers=$(curl --silent --dump-header - --output /dev/null --cookie "CYBERTECH_SECURE_SESSION=$session_id" "$base/api/v1/approval_queue.php?q=$name")
printf '%s' "$headers" | grep -qi 'Cache-Control: no-store'
page=$(get 'control_plane/index.php')
printf '%s' "$page" | grep -q 'id="queueNext"'
printf '%s' "$page" | grep -q 'id="kindFilter"'
printf '%s' "$page" | grep -q 'approval_queue.php'
echo 'PASS: approval queue HTTP authentication, pagination, full search, simulation isolation, expired display, metadata boundaries and invalid filters'
