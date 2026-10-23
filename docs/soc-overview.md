# Evidence-based SOC overview

Open `/soc.php` after signing in. The overview is read-only and available to roles that can view incidents. Refresh reloads stored data; it does not collect feeds, ingest events, calculate risk, send notifications or run playbooks.

## Metric definitions

| Metric / panel | Population and meaning |
| --- | --- |
| Accepted sensor events | All `event_evidence` rows marked non-simulated, joined to their SIEM log. Deduplicated submissions do not create additional evidence rows. |
| Received in 24 hours | The same evidence population with receipt time between the overview's UTC time minus 24 hours and that time, inclusive. Source event timestamps do not determine this count. Future receipts are excluded from this window. |
| Distinct source IPs / severity | The same all-time evidence population. Empty/null source IPs are not counted. Severity uses the SIEM log projection, including `WARNING` for normalized medium severity. |
| Active real incidents | Non-simulated cases in `NEW`, `OPEN`, `INVESTIGATING` or `CONTAINED`. |
| Unassigned active cases / P1 | Subsets of active real incidents with no assigned analyst / saved priority P1. |
| Unchanged for 7+ days | Active real cases whose `updated_at` is at least seven days old, using database record time. Notes and workflow actions do not always change this field. This is not an SLA. |
| Provider listings | Rows in `threat_feed_indicators`. The same indicator listed by two providers counts twice. This is not a count of attacks or unique indicators. |
| Providers represented | Distinct providers with at least one stored listing; not the number of enabled or healthy collectors. |

The event preview includes at most 12 rows, newest receipt first, breaking ties by descending evidence ID. Each message is limited to 500 characters with an explicit full-evidence link when truncated. Source names are claimed by senders; the evidence detail shows the authenticated submitter. The case preview contains up to six active real cases, saved priority first, then oldest creation time and ascending case ID. Links open the existing evidence and incident workspaces with appropriate filters.

Simulated submissions and legacy logs without preserved provenance are excluded from sensor metrics and previews. They remain available through the simulation evidence and legacy SIEM links. External feeds have a separate inventory and collection-health section. Neither an accepted sensor report nor a blocklist listing establishes a confirmed attack.

## Consistency and missing data

Evidence, case and inventory reads use one repeatable-read transaction when the overview owns its connection transaction. A caller's existing transaction is reused and left open. The displayed UTC time anchors the receipt window; case-update age uses the corresponding database `NOW()` value. Feed health is read separately after the snapshot because it also examines live collection locks.

A failing section is marked unavailable, with dashes rather than fabricated zero metrics. Other sections remain usable. An empty but successfully queried section shows zero and an explicit empty state. Database details are logged server-side, not displayed to users.

No new migration is added. The existing evidence schema (008), feed inventory (007), feed collection history (010), and incident simulation classification (011) are required for their respective sections. Follow the existing migration guides rather than recreating a database volume.

Counts are all-time unless explicitly labeled 24 hours. Existing historical logs are not reclassified or backfilled. Aggregate queries can scan large tables; large-volume performance and interactive browser layout remain separate validation work.

CI covers provenance isolation, receipt/source time differences, future receipts, bounded and deterministic previews, workload filters, provider listing semantics, read-only transaction behavior, unavailable versus empty sections, and authenticated HTTP rendering.
