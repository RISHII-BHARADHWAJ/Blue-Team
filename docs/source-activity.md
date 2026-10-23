# Telemetry source activity

Open **Source activity** from the SOC overview or event explorer (`sources.php`). The view is read-only and requires the same `view_alerts` permission as event evidence. It reports activity from preserved, accepted submissions; it does not poll sensors or infer connectivity.

Each row is an exact, case-sensitive pair of **authenticated submitter** and **claimed source name**. Source names are supplied by the sender. A shared API identity can represent several sensors, so these rows are not an inventory of distinct machines. Sources that have never submitted cannot be shown.

The default view includes sensor-reported evidence only. The separate simulated view is explicitly labeled. External feed records, legacy logs without evidence, rejected requests, and duplicate submissions suppressed before storage are excluded. Counts describe stored evidence, not all network requests or detected attacks.

## Time and activity definitions

Choose a one-hour, 24-hour (default), or seven-day receipt window. One database UTC clock is captured per request, and the owned repeatable-read snapshot keeps counts and pages consistent. Borrowed transactions stay under the caller's control.

| Field | Definition |
| --- | --- |
| Receipts in window | `received_at` at or after the window start and at or before the captured UTC clock |
| All stored | All preserved receipts for this identity and evidence kind, including future receipts |
| First / last receipt | Minimum / maximum receipt at or before the captured clock |
| Received in window | At least one qualifying receipt and no future receipt |
| No receipts in window | No qualifying receipt and no future receipt; this is not an outage diagnosis |
| Future receipt recorded | At least one receipt later than the captured clock; this label takes precedence over other activity labels |

Future receipts have a separate count. They cannot establish recent activity or replace the latest non-future receipt. A future-only identity has no first/last non-future receipt. Source-supplied event timestamps do not control this view.

## Search and evidence links

Search source names or submitters with a literal substring of at most 200 UTF-8 bytes. Percent and underscore characters are literal. Search uses the database's text collation; grouping and drill-down identity matching use binary comparison to keep distinct spellings separate.

Pages hold at most 25 identities. Sort by latest receipt, oldest last receipt, or most receipts in the chosen window. Submitter and source names break ties deterministically; identities without a non-future receipt sort last for time ordering. Pagination retains filters and clamps out-of-range pages. New data can shift pages between visits.

**Inspect all preserved events** opens the event explorer with evidence kind, exact source and exact authenticated submitter. It shows the identity's entire stored history, not just the selected activity window. Full Unicode source and submitter values are preserved in links, with validation limits of 400 and 1,020 UTF-8 bytes respectively, matching the maximum encoded size of their database fields. These exact filters are also available directly in the explorer. Selecting a specific event still uses the existing detail behavior.

Unavailable evidence storage produces an explicit 503 error, never a misleading zero count. The feature requires the existing migration 008 and introduces no new migration, scheduled task, provider call or response action.

## Validation

Compose CI covers receipt-time semantics, future receipts, identity separation, simulation isolation, excluded legacy/feed data, literal search, ordering and pagination, exact Unicode drill-down, transaction ownership and missing-schema errors. HTTP checks exercise reader access, escaped names/queries, navigation, preserved filters and method guards. Interactive browser layout testing is not part of these checks.
