# Manual case intake

From the incident queue, select **Report a case** (`incident-new.php`). This workflow records an analyst finding or a report received outside sensor telemetry. If preserved event evidence already exists, use the event's escalation workflow instead. Use the simulated walkthrough for training data.

Enter a title, initial severity and a report explaining what was claimed or observed, its source/time, and why investigation is needed. A named current Tier 2, lead or admin account can submit. The service reloads and locks the account's current database role; bearer automation, unnamed/deleted users, and current Tier 1 accounts cannot create or replay requests. The queue link follows session permissions, while direct intake access uses the database role.

A new case is real (`is_simulated=0`), unassigned and `NEW`. Initial severity maps to priority using the existing case-creation mapping. Risk is initially unassessed at 0. The category and description identify it as a manual report and state that no sensor evidence was attached at creation. The complete report is also saved as a case note attributed to the verified account. The existing creation and note timelines, required note/creation audit records, case and submission mapping commit together.

No logs, preserved events, evidence links, notifications, detections, approvals, playbook runs, or response actions are created by intake. A report is not proof that an attack occurred. After creation, review the report, assign an owner, and link supporting evidence through the existing case workflows.

## Submission identity and failure handling

Each form carries a random 32-character submission key, scoped to the current user. The database binds it to a SHA-256 digest of normalized title, severity and report. Leading/trailing whitespace is trimmed before validation, hashing and persistence.

- Repeating the same key/content returns the existing case without duplicating the report or history, even after the case is renamed or closed.
- Reusing a key with different content returns 409. The form retains the submitted fields and key, with a link to start a separate intake form.
- Concurrent identical submissions produce one case. Conflicting content under one key produces one case and one conflict. Current locking reads preserve these guarantees even inside an older caller snapshot.
- Opening a fresh form creates a new submission identity. Similar content across different keys or users is not automatically deduplicated; review the case queue before creating another report.
- Validation and storage errors retain text fields and the submission key. A database failure rolls back the case, notes, histories and mapping. Retrying after recovery reuses the same intent.
- A caller-owned transaction is preserved with a savepoint; its locks remain governed by that transaction. Committed mappings are retained, and foreign keys prevent deleting their user/case references.

POST uses CSRF protection and rejects extra fields, including author, owner, simulation flags and risk values. Titles are limited to 255 UTF-8 bytes and reports to 10,000 bytes. Reads and form errors are escaped and use `Cache-Control: no-store`. Successful POSTs redirect to the resulting case (303); they never create another case on a subsequent GET. Existing API case-creation routes remain compatible; these submission guarantees apply specifically to this new intake workflow.

## Upgrade existing installations

Back up the database and apply migrations through 012 first. Migration 013 is additive and rerunnable. Apply it before using intake; rebuilding the web container alone does not migrate an existing database volume.

Bash / WSL:

```sh
docker compose exec -T db sh -c 'exec mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' < database/migrations/013_manual_case_requests.sql
docker compose up -d --build web
```

Windows PowerShell (run from the repository directory):

```powershell
Get-Content -Raw database/migrations/013_manual_case_requests.sql | docker compose exec -T db sh -c 'exec mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"'
docker compose up -d --build web
```

These commands use the database container's configured application credentials. If your installation uses a separate migration account, use that account through your established migration process instead. Do not remove an existing database volume to upgrade.

Fresh Compose volumes include 013 automatically. The migration adds `manual_case_requests` with unique user/key and case links; it does not rewrite existing cases or historical evidence. Without the table, intake fails explicitly and creates no case. Other existing workflows do not depend on this new table.

## Verification

CI checks fresh schema initialization and migration reapplication, full report attribution, priority/status defaults, absence of evidence/response side effects, identical/different request retries, concurrent submissions with older snapshots, current-role revocation, malformed input, atomic rollback after audit/final-mapping failures, missing request storage, CSRF, escaped rendering, and form retention. Interactive browser layout and running the upgrade on the user's Windows installation have not been tested.
