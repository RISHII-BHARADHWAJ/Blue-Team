# Incident indicators and saved intelligence

Open **Case indicators → Inspect indicators and saved intelligence** from `incidents.php` to reach `incident-iocs.php?id=<case ID>`.

All authenticated analysts can inspect the case's indicators, filter by type, and select an indicator to see the latest stored result per provider and paginated lookup history. The page does not query providers or write database records on GET. Indicator URLs are displayed as escaped text, never external clickable links. Provider raw responses and arbitrary parsed summary fields are omitted; only provider name, stored status, numeric scores and timestamps are displayed.

## Local discovery

Named Tier 2+ analysts can select **Discover saved indicators**. The POST requires CSRF protection and accepts only the case ID and token. The service reloads the analyst's database role, locks the case, and extracts from attached logs plus preserved canonical event evidence. Canonical destination, IOC and metadata fields supplement fields missing from legacy logs. Existing extractor normalization and exclusions apply; this is not a comprehensive parser for every indicator syntax.

- Adds missing IOC records and case links. Existing registry scores, confidence, timestamps, source and case roles remain unchanged.
- Uses existing role inference. The first occurrence in ascending log-ID order supplies the role for a new link. The schema stores one role per case/indicator; roles remain hypotheses, not proof of malicious activity.
- Makes no external requests, performs no enrichment or response action, and does not change case risk or priority. Use the risk workspace for explicit recalculation after evidence changes.
- Rejects simulated cases and any attached evidence labeled simulated before writing to the shared IOC inventory.
- Limits one discovery to 1,000 alerts and 2,000 distinct candidates. Exceeding a limit fails the whole operation; there is no silent partial result.
- New links, timeline milestone and analyst audit commit together. Errors roll back the operation, including inside a caller-owned transaction using a savepoint. Repeated and concurrent discoveries add only missing links; unchanged retries create no duplicate milestone.

The page uses POST/redirect/GET and reports candidate, scanned-alert and newly linked counts. If new evidence arrives later, another discovery can add its indicators. Discovery counts are not an enrichment success claim. This change introduces no new migration; upgrade existing installations through migration 012 as documented in the README.

## Saved intelligence semantics

The registry is shared across cases. A case's indicator detail shows saved provider results for that indicator, including results collected through other existing workflows. It is not a historical snapshot of the moment the indicator was attached to this case.

The latest row per provider is chosen by `created_at DESC, id DESC`. Only successful, unexpired rows with valid reputation and confidence scores in 0–100 contribute. A newer failure or expired row supersedes an older success; old successes are never revived. Missing or unusable results remain **Unknown**.

Current reputation ≥75 gives **Malicious report**, 25–74 gives **Suspicious report**. A malicious report and another provider's zero reputation with confidence ≥80 gives **Conflicting reports**. Remaining usable reports give **Low reputation reported**, which is not proof that an indicator is safe. Provider reports are not observed attacks.

Indicator and history lists show 25 rows per page. Latest-provider detail is capped at 100 providers; if exceeded, the assessment stays unknown and the UI labels the incomplete view. Historical rows are presented separately and do not contribute to the current assessment. All displayed timestamps use database/server time; expiry is evaluated by database `NOW()`.

This workspace does not change the behavior or response shape of existing enrichment APIs, playbook actions or risk calculations.

## Validation

Compose CI runs `tests/integration_ioc_workspace.php`, `tests/concurrent_ioc_discovery.php`, and `tests/check_ioc_workspace_http.sh`. They cover preserved metadata discovery, exclusions, role/metadata preservation, idempotency, concurrent calls, atomic rollback, simulation blocking, current/expired/failed/conflicting/malformed results, secret-field omission, pagination, and HTTP authentication/CSRF/scoping/escaping. Tests use stored fixtures and no live provider lookups.
