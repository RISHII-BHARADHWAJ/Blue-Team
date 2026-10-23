# Incident queue search and triage views

Open `/incidents.php` after signing in. All incident-viewing roles can use the read-only queue controls. Existing case mutation permissions are unchanged.

- Search matches a literal substring of the incident number or title. `%`, `_` and `!` are ordinary search characters. Matching follows the database collation; the search is limited to 200 UTF-8 bytes and does not search evidence payloads or notes.
- Data defaults to real incidents. Simulated and combined views are explicit choices; simulated rows remain labeled.
- Status, severity, priority, assignment, case state and last-update filters combine. Contradictory filters legitimately return zero results.
- Active means `NEW`, `OPEN`, `INVESTIGATING` or `CONTAINED`. Finished means `RESOLVED` or `CLOSED`.
- Assignment offers anyone, unassigned, or the signed-in user's cases. “Assigned to me” requires a user ID; legacy `mine=1` links still work. It is a convenience filter, not a case access restriction: authenticated viewers retain their existing queue access.
- Last case update offers at least 1, 3, 7 or 30 days ago. It compares `incidents.updated_at` with database `NOW()`. This is case-record age, not time since every analyst action: adding notes, evidence or workflow records does not necessarily update this timestamp. No SLA, escalation or notification is triggered.
- Sorting offers priority first (the existing default), newest, oldest, or least recently updated. IDs break equal-time ties consistently.

Quick links open unassigned active cases and active cases unchanged for at least seven days, retaining the real/simulated data choice. Other filters are reset by those links. Apply filters starts at page one; case links, note pagination and queue pagination retain the selected controls. Excessive page numbers clamp to the last matching page. Each page contains at most 25 cases.

Reads do not change case state, timestamps or notifications. The queue is live, not a saved snapshot: concurrent insertions and case updates can move results between offset-based pages. Repository count and list queries share their predicates, including the older API's category and date filters. Existing API query parameters are unchanged; the new queue controls are currently on the HTML workspace.

No new migration is required beyond the existing schema through migration 012. Search uses bounded output but scans matching titles/numbers; full-text indexing and large-volume performance tuning are not part of this change.

CI runs `tests/integration_incident_queue.php` against a disposable Compose database and `tests/check_incident_queue_http.sh` over HTTP. Integration fixtures roll back; HTTP fixtures are created only in the disposable CI stack. Interactive browser layout and large-dataset performance require separate testing.
