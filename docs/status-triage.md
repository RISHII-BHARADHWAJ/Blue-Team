# Collaborative case status triage

The incident page submits the status it displayed along with the requested next status and reason. If another analyst has moved the case to a different state, the API returns HTTP 409 (`status_conflict`) and the form offers **Reload case**. The reason remains in the form until reload; review the latest state before deciding again.

A request for the already-current status succeeds without changing the case timestamp, lifecycle timestamps, timeline or audit log. The original decision and reason remain intact, even if the retry supplies another reason. Use a case note to record additional findings. Close permission is checked even for retries against an already-closed case.

This protects against a stale but otherwise valid transition: for example, a lead viewing NEW cannot close a now-OPEN case using that stale page. Refreshing the case allows the lead to review OPEN and submit the decision again. The state machine remains unchanged and CLOSED remains terminal. Status changes do not execute containment, enrichment or other response actions.

## API compatibility

`POST /api/v1/incidents_detail.php` accepts the optional `expected_status` field for `action=change_status`:

```json
{
  "id": 42,
  "action": "change_status",
  "new_status": "OPEN",
  "expected_status": "NEW",
  "reason": "Reviewing the submitted evidence"
}
```

Session requests still require a CSRF token. Read-only users cannot mutate cases; normal transitions require Tier 2+, and closing requires Lead/Admin. Existing session/bearer authorization behavior is unchanged.

When supplied, the expected status must be a recognized state string. Values are trimmed and uppercased; null, booleans, arrays, empty strings and unknown states return 422. Target statuses are validated the same way. Reasons must be text or null. Omission preserves the existing API contract and applies the requested transition to the current locked state without a stale-page check. The browser always supplies the expectation.

`IncidentManager::changeStatus($id, $newStatus, $actor, $reason, $expectedStatus)` adds an optional fifth argument; existing callers remain compatible. A successful no-op retains the existing `status_changed` response action for compatibility, with the current case record. Invalid lifecycle transitions return 422; stale expectations return 409; authorization failures remain 403.

## Persistence and concurrent decisions

The service locks the case before checking current status. Same-target concurrent retries produce one actual transition; differing targets with the same expected status produce one winner and one conflict. Current locked case fields are returned even if a caller has an older read snapshot.

Actual transitions persist the status, lifecycle timestamp, timeline and required audit record atomically. Audit or timeline failure rolls back the transition. The service owns a transaction when called independently and uses a savepoint inside an existing transaction, preserving unrelated caller work. No database migration is required.

Compose CI covers sequential and concurrent retries, competing transitions from older snapshots, failed timeline/audit writes, caller transaction ownership, lifecycle timestamps, simulation classification, API validation, CSRF, roles, conflict responses and the form's expected-status field. Browser interaction testing is not included in these HTTP checks.
