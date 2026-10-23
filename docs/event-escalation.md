# Escalate preserved event evidence into a case

In **Event evidence**, inspect a real event with no linked incident, then choose **Review and open an investigation case**. The review page shows the claimed source, authenticated submitter, receipt time, saved severity/category and a bounded message preview. Follow the evidence link to inspect the full submission before acting.

A current, named Tier 2+ analyst account is required. Permissions are resolved from the database user, not a submitted author or a stale session role. Read-only users, unnamed sessions and bearer automation cannot use this analyst workflow. Existing API routes retain their existing contracts.

Enter a case title and explain why the event needs investigation. On submission:

1. The service verifies preserved evidence exists and is not simulated. Legacy logs without provenance cannot be escalated here.
2. If any case is already linked, the workspace opens the earliest linked case without changing it. Closed/resolved cases remain closed/resolved; retries do not duplicate the rationale or create a new case.
3. Otherwise, it creates a NEW, unassigned real case, derives severity/priority and category from the stored canonical alert, and attaches the event with `ANALYST_EVIDENCE_ESCALATION` provenance.
4. It saves the investigation reason as a note attributed to the database user, adds the existing note timeline event, and records an `escalate_event` audit linking the actor, evidence, case and note.
5. The browser redirects to the case after success.

Creating a case does not confirm an attack, run a playbook, collect external intelligence, send a message or perform containment. Later case assignment and workflow actions use their existing controls.

The title is required and limited to 255 UTF-8 bytes. The investigation reason is required and limited to 10,000 UTF-8 bytes. The form explains these byte limits; browser character limits are only an initial convenience. CSRF protection and a strict field allowlist apply to POST requests. The server never accepts severity, simulation classification or author overrides through this form.

## Persistence and retries

Case creation, evidence attachment, rationale and required audit persistence share a transaction. Failure rolls back the whole operation. When called inside an existing transaction, the service uses a savepoint and leaves the caller's transaction open.

Concurrent submissions through this workspace serialize on the evidence row. A current locking lookup for linked cases avoids duplicate creation even when a caller previously established an older read snapshot. The first successful submission wins; later titles/reasons are not appended or substituted. This is workflow-scoped retry protection, not a database-wide ban on linking evidence to multiple incidents through other existing APIs or integrations.

GET requests only review data and establish the session CSRF token; they never create cases. The simulated walkthrough remains the entry point for training cases. No new migration is required beyond the existing evidence and incident schema.

CI verifies persistence and attribution, current-role enforcement, simulation/legacy exclusion, input validation, repeat submissions after closure, rollback on audit failure, concurrent submissions and HTTP authentication/CSRF/rendering. Interactive browser layout has not been tested.
