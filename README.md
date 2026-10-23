# ThreatPulse — Blue Team SIEM + SOAR

> **Status: active development / security lab project.** ThreatPulse combines **Security Information and Event Management (SIEM)** with **Security Orchestration, Automation and Response (SOAR)**. The investigation, correlation and approval workflows are being built incrementally; this is **not a production-ready SOC or automated containment platform**.

ThreatPulse is a PHP and MariaDB-based Blue Team project for collecting and visualizing security events, turning suspicious activity into incidents, enriching evidence, and guiding analysts through auditable response workflows.

## What it does

| SIEM: detect and investigate | SOAR: organize and respond |
| --- | --- |
| Ingest and store event/log data | Validate, normalize and deduplicate alerts |
| Visualize attack trends and source geography | Correlate alerts into incidents |
| Fetch external threat-intelligence feeds | Extract/enrich indicators of compromise (IOCs) |
| Explore logs in the SOC dashboard | Score and prioritize incidents |
| Investigate suspected attacks | Triage, assign analysts, and track case timelines |
| | Run allowlisted investigation playbooks and approval workflows |

**Event flow:** authenticated sensor alert → preserved evidence and SIEM record → configurable detections → incident correlation → investigation → controlled SOAR workflows and audit history. External threat feeds populate a separate intelligence inventory; a feed listing is not an observed attack.

### SIEM capabilities

- **SOC overview:** `soc.php` separates preserved sensor evidence, active real-case workload, and external intelligence inventory, with explicit unavailable states and investigation links. See [metric definitions and provenance](docs/soc-overview.md).

- **Feed health and history:** `feeds.php` shows durable collection outcomes, counts, failures and incomplete imports, with administrator refresh settings. See [migration 010 and scheduling](docs/feed-collection.md).
- **Configurable detections:** `detections.php` exposes authentication-failure and source-IP intelligence findings, evidence links, simulation isolation, and audited administrator settings. Apply migration 009; see [detection rules](docs/detection-rules.md).
- **Event evidence:** `events.php` searches newly accepted submissions and exposes preserved payloads, source attribution, timestamps, metadata, and incident links. See [evidence upgrades and limitations](docs/event-evidence.md).
- **SOC dashboard:** `dashboard.php` visualizes attack activity, categories, source locations and trends.
- **Threat-intelligence ingestion:** `api_fetch.php` and `feodo_realtime.php` collect data from configured external feeds.
- **Geographic context:** geolocation-backed views help analysts explore source IPs.
- **Investigative terminal:** `terminal.php` provides a **simulated** investigative interface; it is not a privileged shell on managed endpoints.

### SOAR capabilities

- **Personal analyst inbox:** `notifications.php` provides unread/all/read views, related-case links and explicit single/batch acknowledgement for named users. See [notification ownership and workflow](docs/analyst-notification-inbox.md).

- **Incident handoff report:** `incident-report.php` combines case state, evidence references, notes and workflow records into a printable summary and JSON snapshot with explicit limits. See [report scope and downloads](docs/incident-handoff-report.md).

- **Incident IOC workspace:** `incident-iocs.php` supports local discovery from saved evidence, type filtering, and saved provider results with explicit freshness and failure states. See [indicator investigation](docs/incident-ioc-workspace.md).

- **Incident playbook workspace:** `incident-playbooks.php` offers step inspection, saved dry-run previews and case-scoped run history. Apply migration 012; see [playbook previews and retries](docs/incident-playbook-workspace.md).

- **Explainable risk workspace:** `incident-risk.php` shows saved scores, factor contributions and history, with explicit Tier 2+ recalculation. Reads never change case priority. See [policy v1.1 and workflow](docs/incident-risk-workspace.md).
- **Simulated incident walkthrough:** `demo.php` connects labeled ingestion, detection, investigation and enforced dry-run playbook previews. See [training workflow and migration 011](docs/simulated-incident-lifecycle.md).

- **Alert ingestion:** `POST /api/v1/alerts.php` validates and normalizes telemetry, applies deduplication, and connects accepted alerts with stored SIEM logs and incident correlation. An accepted alert does **not** automatically initiate containment.
- **Incident management:** `incidents.php` offers title/number search, assignment and case-state filters, case-update age, deterministic sorting, linked SIEM events, and investigation timelines. See [queue controls and time semantics](docs/incident-queue.md). Authorized analysts can progress eligible case statuses and assign cases to eligible analysts.
- **IOC enrichment and risk scoring:** dedicated services and REST endpoints support indicator context and incident prioritization.
- **Playbook engine:** deterministic, allowlisted investigation steps support `DRY_RUN`, execution records, evidence/notes, and approval gates. It does **not** implement live firewall blocking, endpoint isolation, or account disabling.
- **Approval control plane:** `control_plane/index.php` presents review and response workflow details with authorization checks and auditability.
- **Role-aware operations:** server-side permissions distinguish read-only users, analysts, leads, and administrators; privileged incident changes and approvals are restricted.

See the [SOAR documentation](docs/soar/database.md) for database design and the detailed guides below.

## Architecture

| Layer | Main components |
| --- | --- |
| Web interface | PHP pages including `dashboard.php`, `incidents.php`, and `control_plane/index.php` |
| API | `api/v1/` endpoints for alerts, incidents, IOCs, risk, playbooks, approvals and notifications |
| Backend | PHP services under `includes/soar/`, plus existing SIEM ingestion scripts |
| Data | MariaDB: legacy SIEM tables, incident/correlation records, playbook runs, approvals and audit history |
| Local environment | Docker Compose with Apache/PHP and MariaDB |

## Run locally with Docker

Requirements: Docker Engine/Desktop with the Compose plugin.

1. Clone the project:

   ```bash
   git clone https://github.com/RISHII-BHARADHWAJ/Blue-Team.git
   cd Blue-Team
   ```

2. Start the local development stack:

   ```bash
   docker compose up -d --build
   ```

3. Open **http://localhost:8080/** and sign in using your configured local development account. Useful pages:

   - SOC overview: `/soc.php`
   - Event evidence: `/events.php`
   - Feed health and collection history: `/feeds.php`
   - Detection findings and rule settings: `/detections.php`
   - SIEM dashboard: `/dashboard.php`
   - Incident queue: `/incidents.php`
   - Printable handoff/JSON report: follow the Case handoff link inside a case
   - Indicator discovery/saved intelligence: follow the Case indicators link inside a case
   - Risk explanation/history: follow the risk link inside a case
   - Playbook previews/run history: follow the SOAR workflows link inside a case
   - Simulated walkthrough: `/demo.php`
   - Personal notifications: `/notifications.php`
   - SOAR control plane: `/control_plane/index.php`

4. Stop the stack without deleting the database:

   ```bash
   docker compose down
   ```

**Database initialization:** For a **new** MariaDB volume, Compose loads `database.sql`, `database/bootstrap/01_siem_tables.sql`, and SOAR migrations `001` through `006`, then migrations `007` (threat intelligence), `008` (event evidence), `009` (detection rules), `010` (feed collection history), `011` (simulated incidents), and `012` (saved playbook previews), in order. MariaDB initialization scripts **do not run again** for an existing volume. Back up existing data and use a reviewed migration process when upgrading. **Do not delete an existing volume to force migrations.**

**Credentials:** The repository contains development-oriented database and seeded-account settings. Treat them as unsafe defaults: replace passwords/secrets and secure or disable seeded demo accounts before connecting this project to a real network. Do not expose this local stack directly to the internet.

## Manual setup (Apache / XAMPP / MariaDB)

For local development without Compose:

1. Set up PHP, Apache and MySQL/MariaDB, then copy the project into your web root.
2. Create a database named `cybertech_db`.
3. Import `database.sql`, then `database/bootstrap/01_siem_tables.sql`, followed by `database/migrations/001_create_soar_schema.sql` through `012_playbook_previews.sql` **in numeric order** for a new database.
4. Configure the application's database connection (`includes/db.php` and environment/configuration used by the scripts) for your local database. Use non-demo credentials.
5. Open the application through your local web server. Configure scheduled ingestion only after checking feed/network requirements and logging:

   ```cron
   */5 * * * * php /path/to/project/feodo_realtime.php >> /var/log/feodo_realtime.log 2>&1
   */30 * * * * php /path/to/project/api_fetch.php >> /var/log/threat_fetch.log 2>&1
   ```

These schedules are examples, not a requirement for exploring the built-in SOAR workflows.

## Threat intelligence inventory

After migration `007`, Feodo Tracker indicators are stored in `threat_feed_indicators` and displayed at `/threat-intel.php`. These are externally reported indicators, **not** confirmed attacks against your environment. The bulk collector now imports Emerging Threats, CINS Army and Blocklist.de IP reputation lists into the same inventory without fabricating incident events. ThreatFox requires a separate API authentication key and is not automatically queried without one. Historical rows in `logs` are preserved; they are not automatically reclassified.

For an existing local database volume, back up the database first, then apply `database/migrations/007_threat_feed_indicators.sql` using your normal MariaDB migration workflow. Compose only auto-initializes **new** volumes. Do not delete an existing volume to force this migration.

For migration 008 on an existing installation, follow the [non-destructive evidence upgrade instructions](docs/event-evidence.md#upgrade-an-existing-installation) then the [migration 009 detection upgrade](docs/detection-rules.md#upgrade-existing-volumes) before submitting new alerts. Apply [migration 010](docs/feed-collection.md#upgrade-existing-installations) before running the updated feed collectors. Apply [migration 011](docs/simulated-incident-lifecycle.md#existing-database-upgrade) before using simulated incidents or the risk workspace. Apply [migration 012](docs/incident-playbook-workspace.md#upgrade-existing-installations) before using saved playbook previews.

## SIEM alert and threat-intelligence correlation

When an authenticated security sensor submits a valid event to `POST /api/v1/alerts.php`, the existing SIEM-to-SOAR pipeline stores the event and evaluates incident correlation. The response now includes `threat_intelligence.matched` and the matching public-feed records, if the alert's source IP is listed in `threat_feed_indicators`.

Open `/incidents.php?id=<incident ID>` to see the same source-IP reputation context alongside linked SIEM evidence. This lookup is read-only and reflects the **current** inventory; it is not a historical reputation snapshot. Duplicate alerts are still suppressed, and matching a feed cannot automatically trigger containment or alter incident severity.

The backend checks for migration 007 and works without it, returning no matches on older local databases. Data from external blocklists must never be interpreted as proof of activity against this environment.

## Testing and development

The GitHub Actions CI workflow covers PHP syntax checks and database-backed SIEM/SOAR regression tests, including incident workflows and HTTP authorization scenarios. Review the [Actions tab](https://github.com/RISHII-BHARADHWAJ/Blue-Team/actions) for the latest results.

The project is still being developed. Before any deployment beyond a controlled local lab, it needs further work on production secrets and account provisioning, deployment configuration, secure upgrade/migration operations, end-to-end browser coverage, operational monitoring, and isolated, authorized response integrations. **A passing CI run is not a production security certification.**

## Documentation

- [Database architecture and migrations](docs/soar/database.md)
- [Alert ingestion and normalization](docs/soar/alert-ingestion.md)
- [Incident management and correlation](docs/soar/incident-management.md)
- [Analyst case notes and attribution](docs/case-notes.md)
- [IOC enrichment](docs/soar/ioc-enrichment.md)
- [Risk scoring](docs/soar/risk-scoring.md)
- [Playbook engine and dry-run behavior](docs/soar/playbook-engine.md)
- [Approval control plane](docs/soar/approval-control-plane.md)

Some phase-specific design documents describe their original implementation phase; check the code and current tests for subsequent integrations and hardening.
