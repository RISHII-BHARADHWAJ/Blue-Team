# Investigation timeline

Open a case and choose **View and filter full history**, or visit `incident-timeline.php?id=<case ID>`. Any authenticated user with `view_incidents` permission can read the history, including resolved and closed cases. Simulated cases carry an explicit training label and remain isolated by case ID.

The workspace shows 25 entries per page and supports:

- A literal substring search across recorded summaries and actor names (up to 200 UTF-8 bytes, using the database's case-insensitive collation).
- Exact event-type and actor-type filters, combined with the text search.
- Newest or oldest ordering by recorded time, with event ID breaking timestamp ties.

Previous/next links retain filters and case ID. Searches start on page one; out-of-range pages clamp to the last matching page. An owned repeatable-read transaction keeps count and rows consistent within a request. Borrowed transactions remain under the caller's control. History is live: newly appended entries can shift offset-based pages between requests.

This surface reads recorded metadata and summaries, not arbitrary JSON details. It does not search full note bodies or evidence payloads. Follow **Back to case** for notes and linked evidence. All displayed case titles, actor names, summaries and filter values are HTML-escaped. GET is the only supported method and responses use `Cache-Control: no-store`.

The main incident page now requests up to 20 latest summary entries, newest first, with a clear link to the full workspace. `IncidentManager::getIncident($id)` and `IncidentTimeline::getEvents($id)` retain their existing complete chronological history and decoded details for API/internal callers. Only callers explicitly supplying a preview limit receive a bounded summary list. Linked alerts and other case sections retain their existing loading behavior.

No schema migration is required. No timeline writes, provider requests, risk changes or response actions are introduced.

## Validation

The Compose CI job runs `tests/integration_incident_timeline.php` and `tests/check_incident_timeline_http.sh`. Coverage includes literal search characters, combined filters, timestamp ties, page boundaries, case/simulation isolation, legacy manager behavior, transaction ownership, authentication, escaped output, filter-preserving links, invalid inputs and the main-page preview limit. Browser layout validation is not covered by these HTTP tests.
