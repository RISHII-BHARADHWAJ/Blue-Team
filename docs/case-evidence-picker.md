# Link preserved events to an existing case

Open a real incident and choose **Find and link preserved event evidence** below its linked-alert heading. The picker lists real preserved submissions, supports literal message/source-event-ID search and exact source-IP filtering, and shows 25 results per page. Simulated submissions and legacy logs without evidence provenance are excluded. Already-linked events remain visible and are marked explicitly.

Choose **Review event** to inspect a bounded message preview, claimed source, authenticated submitter, event/receipt times and existing case-association count. The full-evidence link opens the original evidence workspace. Source claims and case associations do not independently prove an attack. An event can be linked to several cases; this workflow adds an association, rather than moving the event or merging cases.

Authenticated incident viewers can inspect the picker. A named, current Tier 2+ database account is required to add a link. A stale elevated session role cannot override the database account role. Bearer automation and unnamed sessions cannot submit this analyst action. The existing legacy APIs retain their contracts.

For a new link, enter why this event matters to the case. The UTF-8 reason must contain text and be at most 10,000 bytes. On success, the transaction saves:

- The case/event link with `ANALYST_EVIDENCE_ATTACHMENT` provenance.
- An analyst-attributed `ALERT_ADDED` timeline entry.
- The reason as an attributed case note, including its existing note timeline/audit records.
- An `attach_event_evidence` audit linking the case, event, author and rationale note.

A failure rolls back all these writes. A caller's existing transaction is preserved using a savepoint. POST requests require CSRF and reject unexpected form fields, including author or classification overrides. The browser redirects after success; validation errors retain the selected-event review when available.

## State, retries and side effects

Only active real cases (`NEW`, `OPEN`, `INVESTIGATING`, `CONTAINED`) accept new evidence. The service locks and checks the current case state at submission, so a case closed after review returns HTTP 409. Simulated cases use the training walkthrough instead.

Existing links are successful no-ops, even after closure. Their correlation rule, timestamps and notes are preserved. Repeated or concurrent submissions through the picker save one link and one rationale; later reasons are not appended. Current locking reads handle callers with older transaction snapshots. Other pre-existing case associations remain intact.

This manual association leaves case status, severity, priority, risk and case-update timestamp unchanged. It does not discover IOCs, enrich indicators, execute playbooks, notify users or perform containment. Analysts can use the existing explicit discovery and risk workflows afterward. The original submitted event payload is not rewritten.

No new migration is required. Existing incident, note, audit and event-evidence schemas must be present. Missing/unavailable evidence is reported rather than falling back to unclassified logs. The picker displays at most 200 bytes per table message and 500 characters in the selected preview; full content remains in the evidence workspace.

CI tests search and pagination, read-only access, current-account permissions, classification boundaries, attribution, multiple-case links, provenance preservation, rollback, closed-case conflicts, concurrent submissions and HTTP behavior. Interactive browser layout has not been tested.
