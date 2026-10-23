# Incident handoff report

From case details, select **Case handoff → Print or download an incident report**. `incident-report.php?id=<case ID>` creates a read-only summary containing:

- Case ownership, status, severity, priority and simulation label.
- The latest saved risk assessment, without recalculation or an invented zero-risk assessment when none exists.
- Linked alerts with preserved evidence IDs, sensor attribution and recorded payload hashes.
- Analyst notes, linked indicator roles and evidence artifact references.
- Playbook run modes/statuses, approval records, response-action records and recent timeline summaries.

**Download this snapshot (JSON)** uses the data already embedded in the displayed page. It does not request a newer report. **Print / save PDF** opens the browser's print dialog with a light landscape layout. A no-JavaScript fallback downloads a newly generated JSON snapshot. An authenticated `GET incident-report.php?id=<case ID>&format=json` also generates a fresh JSON attachment.

## Snapshot and scope

Normal web requests read all sections in one repeatable-read transaction. A concurrent change committed after the first case read is visible only to a later report. The service closes transactions it owns and never commits or rolls back a caller-owned transaction; callers supplying one control its isolation level.

The JSON schema is `threatpulse.incident-report.v1`. `generated_at_utc` is explicit UTC; stored record timestamps retain database/server time. The server does not archive reports. Regeneration may differ as the case evolves. This feature needs no new database migration; existing installations should be upgraded through migration 012.

Each section includes `total`, `included`, `limit`, `truncated`, `text_truncated_count`, `order` and `rows`. At most 100 rows are included per section. Description, note and alert message text are capped at 10,000 characters, with explicit per-field flags. If records or text are omitted due to these limits, `partial` is true and the page displays a prominent partial-report notice. This is a bounded handoff summary, not an exhaustive forensic export.

Pinned notes come first, then newest notes; other sections show newest records first. Counts and rows are scoped to the selected case. Approval records are included only when their linked run also belongs to that case. The HTML and JSON both preserve simulation labeling. A completed dry-run is labeled `DRY_RUN`; missing execution mode remains `UNKNOWN`. Snapshot playbook names are preferred; fallback names are labeled `CURRENT_CATALOG`. A pending approval past expiry is labeled `EXPIRED_BY_TIME` alongside its unchanged stored status.

## Data included and excluded

Report generation does not query providers, change risk or case state, execute playbooks, expire approvals, append timeline entries or write audit events. It uses the normal authenticated `view_incidents` permission, including Tier 1 readers. Both formats reject POST and are served with `Cache-Control: no-store`.

Raw event and provider payloads, artifact contents/file paths, approval payloads, playbook contexts/parameters/step output, response output logs and structured timeline details are excluded through explicit field selection. Included notes, alert summaries, indicator values and case descriptions may still contain sensitive material; review before sharing. Display text is HTML-escaped, and `<` characters in the embedded JSON are escaped to prevent script termination. Indicator URLs are plain text.

Evidence hashes are copied from stored records; the report neither retrieves artifact files nor revalidates their bytes. Indicator roles are candidate context, not a current provider verdict. Case status and recorded response statuses are not independent proof of external containment. Risk factor details and full histories remain available in the case workspaces.

## Validation

Compose CI runs integration tests for section scoping, excluded fields, evidence provenance, risk ordering, dry-run/unknown modes, read-only expiry interpretation, row/text limits and caller transaction preservation. A second database connection commits a note midway through report construction to verify count/row consistency and transaction cleanup. HTTP checks cover authentication, Tier 1 exports, download headers, HTML/embedded JSON escaping, simulation/partial labels and invalid requests. Browser print pagination and physical/PDF output require interactive review; CI validates the served HTML and JSON.
