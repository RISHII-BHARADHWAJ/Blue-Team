# Lead/admin audit history

Named users with a current database Lead or Admin role can open **Audit history** (`audit.php`) from the SOC overview. Case pages link to records whose targets directly identify that case. This adds the `view_audit` capability for Lead/Admin; ordinary users, analysts, bearer automation and unnamed sessions cannot read this workspace.

Authorization is checked against the database on every read. Session role claims do not grant access after a downgrade or account deletion. A locking role read also prevents a caller's older repeatable-read snapshot from retaining outdated access. The lock lasts until the owned read transaction ends, or until the caller ends its borrowed transaction. Navigation visibility uses the session role as a convenience; the endpoint remains authoritative.

## Search and time

The view shows 25 records per page and supports literal actor/action substring search, an exact case-sensitive action filter, recorded outcome, inclusive from/through dates, a direct case ID filter, and oldest/newest ordering. Timestamp ties use audit ID. Pagination preserves filters and clamps high page numbers. Date boundaries and displayed timestamps use **database server time**, matching the existing audit schema; they are not silently converted to browser time.

Null outcomes are shown as **Not recorded**, not inferred successes. Future timestamps are displayed as stored. The page describes recorded history only; it does not infer that an action actually succeeded beyond its stored outcome. Successful searches with no matches show zero records; storage failures produce 503 instead of false empty results.

## Visible fields and case links

Rows contain record ID, timestamp, recorded actor, source IP, action, outcome and a recognized case reference. Known credential-like patterns in displayed metadata use the existing notification redactor. This pattern-based treatment is not a guarantee that arbitrary metadata contains no sensitive text.

Raw `details` and `user_agent` are never selected. Target values are used internally only to resolve direct references; arbitrary targets such as terminal commands are not returned or rendered. Case links resolve exact `incident:<ID>` and `INC-YYYY-NNNN` targets to existing case rows. Unknown, missing or embedded references are not turned into links. Simulation badges reflect the linked case's stored classification.

The case filter matches only a case's exact stored number and `incident:<ID>` target. It does not search JSON payloads for hidden references, and cannot claim a complete per-case audit trail: approvals, playbook runs and other operations may target their own objects. Use case timelines and workflow histories for additional context. Audit data itself is application-recorded, not tamper-proof, and older code paths may have incomplete logging.

## Read behavior and verification

The workspace supports GET only, sets `Cache-Control: no-store`, and does not change records, acknowledge events or log extra inspection entries. An owned repeatable-read transaction keeps filters/count/results consistent within a request; borrowed transactions stay under caller control. New audit entries may move offset-based pages between visits.

No database migration is required. Compose CI covers current-role authorization (including a downgrade after a caller's snapshot), exact case resolution, payload omission, metadata redaction, date boundaries, null outcomes, literal searches, pagination, transaction ownership, unavailable storage, HTML escaping and HTTP access controls. Interactive browser layout testing is not included.
