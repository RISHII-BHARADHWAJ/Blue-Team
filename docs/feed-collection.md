# Feed collection health and history

`feeds.php` shows per-provider health, collection history, counts, failure reasons,
last complete success, and refresh settings. The SOC overview and live-status
endpoint read the same database history. Temporary JSON files no longer provide
feed status; existing inventory timestamps do not prove a collector succeeded.

## Upgrade existing installations

Back up the database and keep its volume. Apply migrations through 009 first, then
apply migration 010 **before running the updated collectors**. From the repository
in PowerShell or a Unix shell:

```sh
docker compose cp database/migrations/010_feed_collection_history.sql db:/tmp/010_feed_collection_history.sql
docker compose exec -T db sh -c 'mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" < /tmp/010_feed_collection_history.sql'
docker compose up -d --build
```

Migration 010 adds `feed_sources` and `feed_collection_runs`, with four enabled
source configurations. Rerunning it preserves settings, history and all existing
indicators. New Compose databases initialize it automatically. Non-Compose
installations must apply it manually. No history is invented for old imports.
Rebuild the web image to install the revised cron schedule and startup script;
a source-code bind mount alone does not update `/etc/cron.d/threatpulse`.

## Collection and schedules

- Feodo Tracker defaults to 300 seconds; Emerging Threats, CINS Army and Blocklist.de
  default to 1800 seconds. All intervals can be configured from 60–86400 seconds.
- Cron checks each collector every minute using `--scheduled`. A provider is due
  when its last attempt is at least its interval old, including failed attempts.
  Sub-minute precision is not promised. A failed provider is retried at its next
  interval; missed time does not produce a burst of catch-up runs.
- `php api_fetch.php` and `php feodo_realtime.php` remain manual CLI entry points.
  Manual runs bypass due time but honor disabled settings and concurrency locks.
- Administrators may enable/disable a provider or change its interval. Named user
  identity, current database role, session CSRF and revision checks protect edits;
  before/after settings are audited. Changes affect future attempts. An attempt
  already running may finish using its captured revision.
- Set `FEED_COLLECTION_ENABLED=0` in the Compose environment and recreate the web
  container to pause all background and manual CLI collection. CI uses this switch
  and injected fixture responses instead of external feeds.
- Skipped checks (not due, disabled, or already running) do not create history rows.
  They are reported in CLI output. The history records actual attempted collections.

The four HTTPS URLs are fixed in code. This milestone does not expose arbitrary
URLs, credentials, a browser-triggered fetch, or ThreatFox collection. ThreatFox's
on-demand enrichment is separate. Redirects are rejected and recorded as failures;
review endpoint changes in code if an upstream provider moves its feed.

## Results and data integrity

| Result | Meaning |
| --- | --- |
| RUNNING | An attempt was persisted before fetching; it has not recorded a final result. |
| SUCCESS | A valid response and all accepted indicators committed without invalid/capped omissions. |
| PARTIAL | Valid indicators committed, but invalid rows or the import cap omitted some entries. |
| FAILED | Transport, HTTP, parsing or database failure; no indicator writes from the attempt committed. |
| INTERRUPTED | A process exited without a final result; the next lock owner reconciles its unfinished run. |

Health additionally shows NEVER_RUN, DISABLED and OVERDUE. A complete run is HEALTHY
until its interval plus a two-minute scheduler grace period has elapsed. The history
still retains failures and partial outcomes after newer successes. `last_success_at`
means **complete** success; PARTIAL does not advance it. A global deployment pause is
shown separately. Health describes collection, not correctness of upstream listings.

Each run saves its endpoint, configuration revision, manual/scheduled trigger,
start/end UTC times, elapsed milliseconds, HTTP status, bytes, committed indicator
counts, new/existing counts, invalid/duplicate rows and cap flag. Duplicate IPs are
canonicalized before counting. New/existing counts describe inventory writes, not
new attacks. A repeated unchanged indicator is counted as existing.

Collection uses a connection-owned MariaDB advisory lock scoped to database and
provider; concurrent containers sharing that database cannot collect the same feed
at once. No database transaction stays open while waiting for HTTP. Indicator
upserts and the final successful/partial run result commit atomically. Failed writes
roll back and record zero committed counts. A database outage may prevent recording
a failure itself; the UI can then report unavailable/interrupted state rather than
false success. A RUNNING record with no lock owner displays INTERRUPTED immediately
and is persisted as such at the next collector check.

Responses are limited to 10 MiB, with a 25-second stream timeout. Existing import
caps remain 300 distinct Feodo IPs and 2,000 distinct IPs per plaintext feed; caps
are now visible as PARTIAL. An explicit empty Feodo list is valid. Empty, HTML-only,
malformed or all-invalid plaintext responses fail. Unknown Feodo malware metadata
and invalid source dates remain null rather than being invented. Upstream event
times are parsed as UTC unless they contain an explicit offset.

No feed collector writes SIEM events, detections or incidents. Failed refreshes and
removed upstream entries do not delete existing indicators. Inventory expiry,
provider-specific freshness rules, archival and history retention remain future
work. Run history grows until a reviewed retention mechanism is added.

## Validation

CI uses deterministic fixture responses for parsing, duplicates, timestamp handling,
size/cap limits, due/disabled behavior, two-connection exclusion, interrupted-run
recovery, HTTP/parse failures, atomic rollback after a forced database error, retry,
settings audit/revisions and migration reruns. HTTP checks cover authentication,
permissions, CSRF, escaped rendering, SOC/live-status integration and CLI-only fetch
entry points. Existing detection and SOAR suites continue to run.

No live provider availability, interactive browser rendering, or Windows-localhost
execution is claimed by these fixture tests.
