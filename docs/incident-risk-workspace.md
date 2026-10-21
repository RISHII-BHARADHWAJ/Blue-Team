# Incident risk workspace

Open a case in **Incidents**, then choose **View score explanation and history**. `incident-risk.php?id=<case ID>` shows a saved 0–100 score, assessed priority, evidence confidence, all ten factor contributions, and paginated history. Each historical row opens its stored breakdown. The current case priority is displayed separately because later incident correlation may change it.

An unassessed case displays **No saved risk assessment**, not a misleading zero-risk conclusion. Page/API reads do not calculate, update priority, create history, or contact intelligence providers. Each explicit **Recalculate risk and priority** action saves a new assessment, applies the resulting priority, and writes the normal audit/timeline records. Recalculation can lower as well as raise priority. It does not execute a playbook, contact a host, enrich an IOC, or initiate containment.

Tier 1 can read. Tier 2+ can recalculate with session CSRF protection; a session must identify a named database user, whose current role and username are checked again inside the write transaction. Configured bearer automation retains its existing recalculation capability. A caller cannot supply score, priority or asset criticality. Simulation labels remain visible; recalculating a training case only changes that case.

## Policy v1.1

Weights and priority thresholds stay unchanged (P1 ≥90, P2 ≥75, P3 ≥50, P4 <50); corrected evidence handling can change scores:

- **Recency:** use the latest valid non-future alert timestamp in UTC. Old timestamps no longer receive the maximum freshness contribution. Missing, invalid and future-only timestamps add zero recency points.
- **Volume:** a case without attached alerts reports zero alerts. Legacy `WARNING` maps to canonical `MEDIUM` severity.
- **Network context:** require a source/destination pair in the same event. The engine reads the destination from preserved canonical evidence; source-only legacy logs contribute no topology points. Private/public address classes are an IP-address heuristic, not an asset inventory. Documentation, shared and benchmarking ranges are excluded from public exposure evidence.
- **Intelligence:** use only the latest stored row per IOC/provider, ordered by creation time then ID, and only if successful and unexpired. Failed/expired latest rows do not fall back to old successful claims. Free-text threat labels do not become malicious assessments. Provider reputation ≥75 is malicious; ≥25 is suspicious; malicious and high-confidence clean reports yield conflicting evidence. Distinct IOC roles do not duplicate an indicator. Confidence from benign indicators cannot boost malicious confidence.
- **Category patterns:** co-occurring categories remain weighted heuristics, not verified attack sequences. Scores and confidence are not probabilities of compromise.
- **Unknown assets:** asset inventory is not connected to this workspace, so that factor stays neutral.

Existing v1.0 assessments remain untouched and labeled with their original policy. New calculations are v1.1. Stored breakdowns preserve the assessment's recorded reasoning; the case evidence link shows current case evidence, not a complete historical input snapshot. Recalculation intentionally uses current stored intelligence and time.

## API and storage

`GET /api/v1/incidents_risk.php?id=<id>&page=1` is now strictly read-only. `data.latest` is null for an unassessed case; history is 25 rows per page with `data.pagination`. Unknown cases return 404. This replaces the former automatic calculation on GET and unbounded history behavior.

`POST /api/v1/incidents_risk.php` accepts JSON `{ "incident_id": 123 }` with the session's `X-CSRF-Token` (or the configured bearer token). A successful response includes the computed assessment and verified actor. JSON score/priority/asset overrides are rejected. Each successful POST adds a history entry; after an ambiguous network failure, check history before retrying.

Recalculation starts a transaction before locking/reading the incident and commits history, priority, timeline and audit together. Nested callers use savepoints; failures roll back this operation without rolling back unrelated caller work. Same-second assessments are ordered by ID. No new migration is needed beyond the current schema through **011**; destination provenance requires migration 008 and simulation classification requires 011.

## Verification

CI covers recency boundaries, unknown topology, severity normalization, cached intelligence freshness/replacement/conflicts, historical preservation, pagination, audit-failure rollback, database role revocation, HTTP read-only behavior, CSRF, malformed/tampered requests, historical incident scoping and HTML escaping. These are disposable database and HTTP fixtures, not live provider or Windows collector tests. Interactive browser appearance is not covered.
