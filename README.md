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

**End-to-end flow:** telemetry / threat feeds → SIEM logs and dashboard → normalized alerts → incident correlation → IOC enrichment and risk assessment → analyst triage → approval-gated SOAR playbooks and audit trail.

### SIEM capabilities

- **SOC dashboard:** `dashboard.php` visualizes attack activity, categories, source locations and trends.
- **Threat-intelligence ingestion:** `api_fetch.php` and `feodo_realtime.php` collect data from configured external feeds.
- **Geographic context:** geolocation-backed views help analysts explore source IPs.
- **Investigative terminal:** `terminal.php` provides a **simulated** investigative interface; it is not a privileged shell on managed endpoints.

### SOAR capabilities

- **Alert ingestion:** `POST /api/v1/alerts.php` validates and normalizes telemetry, applies deduplication, and connects accepted alerts with stored SIEM logs and incident correlation. An accepted alert does **not** automatically initiate containment.
- **Incident management:** `incidents.php` displays a searchable incident queue, linked SIEM events, and investigation timelines. Authorized analysts can progress eligible case statuses and assign cases to eligible analysts.
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

   - SIEM dashboard: `/dashboard.php`
   - Incident queue: `/incidents.php`
   - SOAR control plane: `/control_plane/index.php`

4. Stop the stack without deleting the database:

   ```bash
   docker compose down
   ```

**Database initialization:** For a **new** MariaDB volume, Compose loads `database.sql`, `database/bootstrap/01_siem_tables.sql`, and SOAR migrations `001` through `006`, then threat-intelligence migration `007`, in order. MariaDB initialization scripts **do not run again** for an existing volume. Back up existing data and use a reviewed migration process when upgrading. **Do not delete an existing volume to force migrations.**

**Credentials:** The repository contains development-oriented database and seeded-account settings. Treat them as unsafe defaults: replace passwords/secrets and secure or disable seeded demo accounts before connecting this project to a real network. Do not expose this local stack directly to the internet.

## Manual setup (Apache / XAMPP / MariaDB)

For local development without Compose:

1. Set up PHP, Apache and MySQL/MariaDB, then copy the project into your web root.
2. Create a database named `cybertech_db`.
3. Import `database.sql`, then `database/bootstrap/01_siem_tables.sql`, followed by `database/migrations/001_create_soar_schema.sql` through `007_threat_feed_indicators.sql` **in numeric order** for a new database.
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

## Testing and development

The GitHub Actions CI workflow covers PHP syntax checks and database-backed SIEM/SOAR regression tests, including incident workflows and HTTP authorization scenarios. Review the [Actions tab](https://github.com/RISHII-BHARADHWAJ/Blue-Team/actions) for the latest results.

The project is still being developed. Before any deployment beyond a controlled local lab, it needs further work on production secrets and account provisioning, deployment configuration, secure upgrade/migration operations, end-to-end browser coverage, operational monitoring, and isolated, authorized response integrations. **A passing CI run is not a production security certification.**

## Documentation

- [Database architecture and migrations](docs/soar/database.md)
- [Alert ingestion and normalization](docs/soar/alert-ingestion.md)
- [Incident management and correlation](docs/soar/incident-management.md)
- [IOC enrichment](docs/soar/ioc-enrichment.md)
- [Risk scoring](docs/soar/risk-scoring.md)
- [Playbook engine and dry-run behavior](docs/soar/playbook-engine.md)
- [Approval control plane](docs/soar/approval-control-plane.md)

Some phase-specific design documents describe their original implementation phase; check the code and current tests for subsequent integrations and hardening.
