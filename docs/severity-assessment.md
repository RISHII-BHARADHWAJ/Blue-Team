# Lead/admin severity assessment

The case page now offers a **Severity assessment** form to named lead/admin sessions on non-closed cases. It posts to `api/v1/incident_severity.php` and requires a reason. The server checks the account's current database role, so a downgraded or deleted account cannot use an old privileged session. Bearer automation and unnamed sessions cannot submit this action. A stale lower session may hide the form even when the database role permits a direct API request; sign in again to refresh navigation permissions.

## What changes

A changed severity sets the case priority using the existing severity mapping:

| Severity | Priority |
| --- | --- |
| CRITICAL | P1 |
| HIGH | P2 |
| MEDIUM | P3 |
| LOW / INFO | P4 |

The case update, full assessment reason in an attributed case note, `SEVERITY_CHANGE` timeline event, and `change_incident_severity` audit record commit together. Timeline/audit details include old/new values and the note ID; the note retains the full reason. The author comes from the current database account, not a client-supplied display name. The saved risk score, risk assessment history, case lifecycle and evidence are unchanged. No response action or playbook runs.

This is a severity assessment, not a persistent priority override. Later risk recalculation or automatic escalation from attached evidence can change priority again. Existing automatic severity escalation remains in place.

## Stale pages, retries and failures

The form sends the severity and priority displayed when it loaded. For a different target severity, both values must still match the locked case; otherwise the API returns 409 and the form retains the reason with a reload link. This also detects a priority change from intervening risk calculation. Concurrent conflicting assessments serialize on the case lock and only the first succeeds.

If the requested severity already equals the current severity, the action is a no-op even if the expected values are stale. It does not reset a later risk-derived priority, refresh timestamps, or add duplicate history/notes. Authorization and closed-case checks still apply. A no-op response does not save a newly entered reason; use ordinary case notes to add context without changing severity. These are value-based checks, not a version history check: a value that changes and later returns to the original value cannot be distinguished by this endpoint.

Closed cases reject every severity request, including repeats, with 409. Missing cases return 404, forbidden identities 403, invalid inputs 422, and storage failures 503. Failure of any required write rolls back the complete assessment. A caller-owned transaction remains open using a savepoint; locks remain governed by that transaction. Locking reads also prevent old caller snapshots from retaining a revoked role or returning stale case values.

## API and validation

POST requires a named session, CSRF header, and JSON object containing only `incident_id`, `severity`, `expected_severity`, `expected_priority`, and `reason`. Severity/priority values are uppercase enums. Reasons must be nonblank valid UTF-8, at most 2,000 bytes. The request body is capped at 16 KiB. Clients cannot specify the author, resulting priority, or audit metadata. Responses use `Cache-Control: no-store`.

No database migration is required. CI covers role changes, stale caller snapshots, reason preservation and output escaping, unchanged risk/lifecycle fields, no-op retries, closed cases, simulation labels, atomic rollback, concurrent identical/conflicting requests, HTTP authorization/CSRF/validation, and client behavior using a minimal DOM. Interactive browser layout testing has not been performed.
