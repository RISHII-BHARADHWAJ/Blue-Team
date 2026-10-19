#!/usr/bin/env bash
set -euo pipefail

base_url="${1:-http://localhost:8080}"
for path in /database.sql /database/verify_schema.php /includes/config.php; do
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' "${base_url}${path}")
  if [[ "$status" != "403" ]]; then
    echo "Expected HTTP 403 for ${path}, got ${status}" >&2
    exit 1
  fi
done
printf 'Internal project files are not exposed over HTTP.\n'
