#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://localhost:8080}"
for path in /reset_db.php /db_test.php; do
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' "${base_url}${path}")
  if [[ "$status" != "404" ]]; then
    echo "Expected HTTP 404 for ${path}, got ${status}" >&2
    exit 1
  fi
done
printf 'Maintenance endpoints are unavailable over HTTP.\n'
