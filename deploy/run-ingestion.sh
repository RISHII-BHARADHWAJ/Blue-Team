#!/usr/bin/env bash
# Cron starts with a minimal environment. Load the runtime DB configuration
# written by start.sh without placing credentials in the public web root.
set -euo pipefail

case "$1" in
    feodo_realtime.php|api_fetch.php) job="$1" ;;
    *) echo "Unsupported ingestion job." >&2; exit 2 ;;
esac

config=/run/threatpulse/ingestion.env
if [[ ! -r "$config" ]]; then
    echo "Ingestion runtime configuration is missing." >&2
    exit 1
fi

# The configuration is generated using Bash %q escapes; it is not user input.
# shellcheck source=/dev/null
source "$config"
cd /var/www/html
exec /usr/local/bin/php "$job"
