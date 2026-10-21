# Incident playbooks and saved previews

Open a case in **Incidents**, then select **Inspect playbooks and run history**. `incident-playbooks.php?id=<case ID>` connects the playbook catalog, previews and saved results to a specific case.

1. Browse the active catalog (10 definitions per page), and select **Inspect steps**.
2. Review the current version, actions, parameters/templates and branch targets.
3. Select **Run saved preview**. Any signed-in named analyst, including Tier 1, may preview. The service reloads the account from the database; bearer automation cannot launch through this page.
4. Inspect the persisted run status and each step attempt. A failure remains a FAILED run with its result; it is not reported as a successful preview. A completed DRY_RUN means only that preview steps finished.
5. Browse this case's run history (25 per page), including previews and executions started through existing workflows. Historical runs without a definition snapshot are explicitly labeled; current catalog contents are not presented as their historical definitions.

The workspace always starts **DRY_RUN** and rejects submitted execution modes or arbitrary fields. It does not query external providers, send notifications, append case notes, create forensic evidence, submit approvals, or perform containment. The request, run, step results, definition snapshot, timeline and normal engine audit records are intentionally persistent. Real case status and priority do not change. Simulated cases retain their labels and forced dry-run behavior.

## Retries and definition changes

A per-user request key binds one case, playbook and version to one preview run. Repeating that submission returns the same run, including a FAILED run. Reusing a key for another intent is rejected. Reload the definition page to create a new request. Concurrent identical requests serialize and produce one run/result set.

The preview checks the active flag and submitted version before execution, validates nonempty steps and stores the definition used in `execution_context.definition_snapshot`. Later definition edits do not change that snapshot. Replaying an already completed request returns its old run even if the catalog has since changed. Creating a new preview against a stale version or disabled playbook is rejected.

The request mapping, run and snapshot use one transaction with nested savepoints. An unexpected exception rolls back the preview operation. Deliberate engine outcomes such as FAILED persist for investigation. The existing engine caps execution at 100 step iterations; branching and retries are represented by recorded attempts, not a claim that every catalog step executed.

## Dry-run approval correction

`REQUEST_APPROVAL` now returns a successful **preview** result for every dry-run context, including ordinary real cases. It does not create a real approval request or pause that preview. Live runs still pause and create approval requests through the existing engine. Historical approval requests created by earlier dry-runs are not silently deleted or processed.

This workspace adds no live-execution control. Existing execution and approval APIs remain separate; their presence is not a claim that firewall blocking, endpoint isolation, or account disabling is implemented.

## Upgrade existing installations

Back up the database and apply migrations through 011 first. Apply the additive, rerunnable migration before using this workspace:

```sh
docker compose exec -T db sh -c 'exec mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' < database/migrations/012_playbook_previews.sql
docker compose up -d --build web
```

Fresh Compose databases include 012 automatically. This adds `playbook_preview_requests`, with a unique user/request key and run linkage. Do not remove an existing database volume to upgrade.

## Verification

CI verifies all six allowlisted actions on a real-case dry-run, preserved live approval gates, simulation compatibility, saved definition history, version/inactive/invalid checks, failed-run persistence, request replay, concurrent duplicate submissions, pagination, HTTP CSRF and identity checks, case-scoped run access and escaped rendering. Fixtures use disposable Compose databases without external provider requests. Interactive browser appearance, Windows collection and live response integrations are not covered.
