# Simulated incident walkthrough

`demo.php` is a persistent training workflow. A signed-in Tier 2 analyst or higher can create a case; other signed-in analysts can inspect it. The creator can run its saved playbook preview once. The service rechecks the account's database role for each write.

1. Open **Incident queue → Simulated incident walkthrough**.
2. Create a simulated incident. The current enabled `auth_failures` rule determines event count (1–100) and case severity. Disabled rules produce an explanatory error and no partial demo. Rule settings stay unchanged.
3. Inspect the finding, saved rule snapshot and supporting event evidence. The source is unique to this demo, the address is documentation-only `192.0.2.55`, and every event carries `is_simulated=true`.
4. Open the case, add an analyst note, assign responsibility, and progress NEW → OPEN → INVESTIGATING → RESOLVED. Closing still requires Lead/Admin. Status changes describe training progress, not real containment.
5. Return to the walkthrough and run the preview. It saves a DRY_RUN run and individual results for context collection, approval and notification. It sends no notifications and creates no approval requests. Completed means the preview completed.

## Isolation and retries

- Ordinary simulated ingestion continues to save evidence/findings without opening cases. Only the dedicated demo service creates these training cases.
- Existing cases default to `is_simulated=0`. The repository rejects changes to that classification and rejects evidence attachment across classifications in both directions.
- Real correlation, the default incident list/API/count and the SOC incident summary exclude simulated cases. `incidents.php?kind=simulated` and `api/v1/incidents.php?kind=simulated` show training cases; `kind=all` explicitly includes both. Direct case links remain available and labeled. Legacy log views may still show the existing `[SIMULATED]` event prefix.
- Every playbook started for a simulated incident is forced to DRY_RUN from authoritative case state, even when MANUAL/AUTOMATIC is requested. Reconstructed playbook contexts also force DRY_RUN, including approval resume paths. Simulated approval actions produce preview results, not real approval requests.
- Live incident IOC discovery/enrichment is rejected before any IOC write or provider call. Training case notes, timeline entries, evidence ingested through the pipeline, audit records, and run results are intentionally persistent.
- A per-user request key makes retrying the same create submission return the same case. A new start form generates a new key. Preview retries return the same run; creation/preview each use one transaction with nested savepoint support. Detection rule locks serialize creation with ingestion/config changes.
- Training cases share the incident number sequence. They are retained for review; this feature does not delete or reset production data.

## Existing database upgrade

Back up the database and apply migrations through 010 first. Then apply the additive, rerunnable migration before running the updated PHP code:

```sh
docker compose exec -T db sh -c 'exec mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' < database/migrations/011_simulated_incidents.sql
docker compose up -d --build web
```

Fresh Compose databases apply 011 automatically. The migration adds the classification column, demo session table and a named manual walkthrough playbook. Reruns preserve existing records/settings; the seeded playbook has no automatic trigger. Do not remove the database volume to upgrade.

## Verification

CI runs database-backed `tests/integration_demo.php` and `tests/check_demo_http.sh`. Coverage includes rule preservation, retry identity, real/simulated evidence separation, generic ingestion behavior, lifecycle notes/status, forced dry-run for all six current allowlisted actions, no live side effects, revoked roles, HTTP CSRF and persisted preview rendering. These tests use disposable Compose fixtures. They do not validate Windows collectors, external providers, or interactive browser appearance.
