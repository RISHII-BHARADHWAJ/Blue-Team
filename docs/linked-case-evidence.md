# Browse linked case evidence

From a case, choose **Search all linked evidence** (`incident-linked-evidence.php?id=<case ID>`). The workspace shows existing case/log associations, including for resolved, closed and simulated cases. It requires `view_incidents` permission and supports GET only. It never adds, removes or reclassifies links.

Search combines:

- Literal substring matching on the full stored log message or preserved source event ID (up to 200 UTF-8 bytes).
- Exact source IP (up to 45 bytes) and source severity; MEDIUM maps to the SIEM log's WARNING value.
- All linked logs, preserved submissions only, or legacy logs without preserved provenance.
- Newest/oldest event time or most recent attachment time, with link ID breaking ties.

The page shows 25 rows at a time and retains filters in pagination links. Out-of-range pages clamp to the last page. An owned repeatable-read snapshot covers case lookup, count and results; caller-owned transactions are left open. New links can shift pages between visits.

## Provenance and time

Preserved submissions show claimed source, authenticated submitter, receipt time, real/simulated classification and a link to the full evidence explorer. Event ordering uses the preserved event timestamp when available, otherwise the legacy log timestamp. Preserved event and receipt times are UTC; legacy timestamps and attachment timestamps use database server time.

Legacy rows are explicitly labeled **provenance unavailable**. They are not assigned fabricated source identities or original-payload links. Their stored log messages remain searchable, and the workspace shows bounded previews. Case and evidence simulation labels reflect their respective stored classifications. A correlation rule or association is recorded context, not proof of malicious activity.

The existing **Find and link additional preserved evidence** workflow remains available for real cases. Its existing permissions and closed-case restrictions still apply. Simulated cases do not offer that mutation link.

## Bounded previews and compatibility

Workspace messages are selected as at most 500 characters, with explicit truncation labels. Search still uses the full stored log message. Raw payloads and normalized JSON are not loaded into result rows. Preserved evidence links open the full inspector; legacy logs have no original payload to inspect.

The main case page now requests up to 20 alerts ordered by the SIEM log timestamp and link ID, shows the complete association count, and links to this workspace. Message previews are limited to 500 characters in SQL. Source-IP intelligence context on the main page is computed for these displayed alerts. Timeline previews remain limited to 20 entries.

The limits are opt-in through `IncidentManager::getIncident($id, $timelineLimit, $alertLimit)` and `IncidentRepository::getAttachedAlerts($id, $limit)`. Existing calls without an alert limit, including the incident detail API, still return every linked alert and its full message. The extra `alerts_total` field is present only with the preview limit. Other case sections retain their existing behavior.

No migration is introduced. The workspace uses existing evidence migration 008; unavailable tables raise an explicit error rather than misclassifying every record as legacy.

## Validation

Compose CI verifies search/filter intersections, literal special characters, event/link ordering, case and simulation isolation, legacy provenance, Unicode-safe truncation, full-message search, caller transaction ownership, missing storage, reader access, escaping, pagination, closed cases, the 20-alert main preview and unchanged API completeness. Interactive browser layout testing is not included.
