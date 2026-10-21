# Analyst case notes

The incident workspace now displays existing case notes, allows signed-in users
with `add_notes` permission (including Tier 1) to append investigation findings,
and pages through older notes. Case notes do not grant permission to triage,
assign, resolve, or close incidents. Notes may be appended to a closed case for
post-incident findings without reopening it.

No new migration is needed: this uses `case_notes`, `incident_timeline`, and
`audit_log` from the existing schema. No edit or delete endpoint is introduced.
Notes are escaped as text in HTML, preserving multiline content without running
scripts or interpreting markup. The UI retains text after a failed save and
prevents repeated clicks while a request is in flight. After an ambiguous network
failure, check the case before retrying; the endpoint has no retry idempotency key.

## API

`POST /api/v1/case_notes.php` accepts JSON:

```json
{"incident_id": 123, "note": "Reviewed the linked SSH events. Waiting for sensor owner confirmation."}
```

A verified browser session and `X-CSRF-Token` are required. The author comes from
the session's user ID and is resolved against the database; client `author_id`
fields are ignored. The shared machine bearer key cannot impersonate an analyst.
A successful `201` response contains the saved note ID, incident ID and author ID.
Blank notes, invalid text types, and notes over 10,000 UTF-8 bytes are rejected.
The API returns 401 for missing authentication, 403 for identity/CSRF failures,
404 for a missing case, and 422 for invalid note content.

The note, `NOTE_ADDED` timeline entry, and audit reference commit atomically.
Timeline/audit records reference the note; they do not duplicate its potentially
sensitive content. Nested service calls use a savepoint so a failed write leaves
no partial note and preserves the caller's transaction.

## Playbook notes

`ADD_INCIDENT_NOTE` now uses the same service and verified execution-context analyst
ID. It no longer silently attributes every note to database user 1. An execution
without a named actor fails with an explicit action result; a dry run still returns
a preview and does not write. Existing historic notes retain their stored author;
this change cannot retrospectively prove their original attribution.

## Checks and limitations

CI adds transactional MariaDB coverage for exact text, authorship, timeline/audit
references, invalid input, pagination, rollback, unchanged incident status, and
playbook attribution. HTTP tests cover anonymous rejection, CSRF, Tier 1 note access,
author spoofing resistance, escaped rendering, and absence of Tier 2 triage controls.

This is application-level append-only behavior. Existing schema delete cascades and
privileged database access still apply; this is not an immutable compliance archive.
There are no note attachments, editing, pinning controls, or full-text search in this
milestone. Browser interaction and the owner's Windows installation need separate
validation.
