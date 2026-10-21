# Durable event evidence and investigation

## Upgrade an existing installation

Back up your existing MariaDB database using your normal backup procedure. Keep
its Docker volume. Apply migrations 001–007 if they are not already installed,
then apply **008_event_evidence.sql before running the new ingestion code**.
Current application versions also require [migration 009](detection-rules.md#upgrade-existing-volumes).
Migration 008 adds one table; it does not update or delete any existing records.
It is safe to re-run because it uses `CREATE TABLE IF NOT EXISTS`.

From the repository directory, these commands also work in PowerShell:

```powershell
docker compose cp database/migrations/008_event_evidence.sql db:/tmp/008_event_evidence.sql
docker compose exec -T db sh -c 'mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" < /tmp/008_event_evidence.sql'
docker compose up -d --build
```

Use the database account configured for your installation. The command reads the
existing container environment; do not put credentials in source control. A new
Compose database initializes migration 008 automatically. An existing volume does
not re-run initialization scripts. Never remove the volume to force migration.
If rolling application code back, leave this additive table and its evidence intact.

## What is retained

`POST /api/v1/alerts.php` keeps its authentication and CSRF requirements. A newly
accepted response includes `log_id` and `evidence_id`. The same database transaction
persists the legacy SIEM log, evidence, deduplication entry, and incident correlation.
Failure rolls them back, including when the pipeline is called inside another
transaction. Retries after a rollback are not suppressed by a stale memory entry.

Evidence stores:

- Exact HTTP body and a SHA-256 checksum of those bytes. Authentication headers
  are not captured. Direct PHP callers without a body store re-encoded JSON,
  explicitly labeled as such.
- The normalized alert, including destination, protocol, metadata, and source ID.
- Claimed source name/type separately from the authenticated submitting actor.
  The shared bearer key identifies the automation channel, not an independently
  verified sensor identity.
- UTC event and receipt times. The source's original timestamp is also retained
  in the submitted body. Missing source time is labeled `receipt_fallback`.
- An explicit simulation flag. No update/delete operation is exposed by the evidence
  repository. The checksum is not a digital signature or protection against a
  privileged database operator changing both the payload and hash.

Existing burst deduplication still uses five-minute event-time buckets and a
five-minute registration TTL. A supplied `source_event_id` now participates in the
fingerprint, so distinct observations with otherwise identical content survive.
Same-ID submissions with changed content/time may be separate observations; this
is not permanent source-ID idempotency. Deploying the changed fingerprint can
accept one repeat during the transition. Database deduplication fails closed and
uses atomic registration for concurrent copies of the same fingerprint.

## Investigate

Open `/events.php` after signing in. Search messages and source event IDs, filter
by exact source name, source IP, source severity, UTC date range, and simulation
status, and page through results. `MEDIUM` maps to the legacy `WARNING` storage
value. Inspect an event to see its original message, normalized metadata, submitted
payload, authenticated actor, checksum, and linked incident. Incident alert links
return directly to this evidence view.

The view includes only newly accepted submissions with durable provenance.
External indicators remain in `/threat-intel.php`. Older mixed `logs` rows remain
in the legacy dashboard and are not retroactively relabeled as observed telemetry.
A sensor's severity/classification remains a source claim. The [detection engine](detection-rules.md)
now generates separate findings and preserves the original submitted severity.

## Simulated submissions

Set the **top-level JSON boolean** `"is_simulated": true` for test telemetry.
Strings such as `"false"` are rejected. Omission defaults to sensor-reported data;
only submit genuine authorized telemetry without this flag.

Simulated payloads retain their original message in evidence; the legacy log message
gets a `[SIMULATED]` prefix. Simulated events use a separate deduplication fingerprint,
return correlation decision `SIMULATION_ONLY`, and cannot be automatically correlated,
manually escalated, or attached to real incidents. They do not execute playbooks.
A separately labeled demo incident lifecycle is still pending. Existing dashboard
aggregate counts include stored simulated log rows; use the explorer's simulation
filter when distinguishing them. Historical unmarked test data is not inferred.

## Validation and remaining work

CI runs `tests/integration_event_evidence.php` against the isolated Compose MariaDB
with rollback-only fixtures. It covers byte preservation, hashes, metadata, incident
links, deduplication, distinct event IDs, nested transaction rollback/retry, simulation
isolation, filtering, pagination, malformed input, and UTC normalization.
`tests/check_event_evidence_http.sh` checks authentication, Tier 1 read access,
HTML escaping, simulation labels, and bad-date responses in the disposable stack.
These are HTTP checks, not interactive browser testing.

Still pending: independently registered sensors, collection history, retention/archival policies,
a full simulated case lifecycle, unified navigation across all legacy screens,
and complete browser validation. Raw submitted evidence can include sensitive
sensor data; collection should avoid credentials and unnecessary personal data.
