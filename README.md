# ThreatPulse — Blue Team SIEM + SOAR

> **Status: feature-complete local lab/demo; release acceptance remains open.** ThreatPulse combines **Security Information and Event Management (SIEM)** with **Security Orchestration, Automation and Response (SOAR)**. The planned investigation workflows, redesigned interface, continuous simulation and light/dark themes are implemented. Docker Compose is the supported local setup. Production SOC deployment and live endpoint containment are outside this project’s completed feature scope.

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

- **Telemetry source activity:** `sources.php` shows receipt windows and last-seen times for preserved submitter/source identities, with exact evidence links. This measures stored activity, not sensor health. See [source activity and coverage](docs/source-activity.md).

- **SOC overview:** `soc.php` separates preserved sensor evidence, active real-case workload, and external intelligence inventory, with explicit unavailable states and investigation links. See [metric definitions and provenance](docs/soc-overview.md).

- **Feed health and history:** `feeds.php` shows durable collection outcomes, counts, failures and incomplete imports, with administrator refresh settings. See [migration 010 and scheduling](docs/feed-collection.md).
- **Configurable detections:** `detections.php` exposes authentication-failure and source-IP intelligence findings, evidence links, simulation isolation, and audited administrator settings. Apply migration 009; see [detection rules](docs/detection-rules.md).
- **Event evidence:** `events.php` searches newly accepted submissions and exposes preserved payloads, source attribution, timestamps, metadata, and incident links. See [evidence upgrades and limitations](docs/event-evidence.md).
- **Telemetry atlas:** `dashboard.php` explores legacy logs, categories and source geography. Historical feed imports and simulated records may appear here; use the SOC overview and Event evidence for preserved sensor activity.
- **Threat-intelligence ingestion:** `api_fetch.php` and `feodo_realtime.php` collect data from configured external feeds.
- **Geographic context:** geolocation-backed views help analysts explore source IPs.
- **Investigative terminal:** `terminal.php` provides a **simulated** investigative interface; it is not a privileged shell on managed endpoints.

### SOAR capabilities

- **Manual case intake:** named Tier 2+ analysts can report a case without inventing sensor evidence, with an attributed initial report and durable retry protection. Apply migration 013; see [manual intake and upgrades](docs/manual-case-intake.md).

- **Lead/admin severity assessment:** update case severity and mapped priority with a required reason, current-role checks, stale-value conflicts, and atomic case-note/timeline/audit history. See [severity assessment and retry semantics](docs/severity-assessment.md).

- **Searchable approval queue:** the control plane searches all requests with paginated results, full-result counts, priority/expiry ordering, and explicit simulation views. See [queue semantics and expiration](docs/approval-queue.md).

- **Lead/admin audit history:** `audit.php` searches recorded action metadata with outcome/date filters and recognized case references, enforcing current database roles. See [audit visibility and limits](docs/audit-history.md).

- **Linked case evidence:** search existing case associations by message/source event ID, source IP, severity and provenance, with separate event/link ordering. Main case pages show bounded previews. See [linked evidence browsing](docs/linked-case-evidence.md).

- **Collaborative case triage:** status submissions from the case page reject stale states, treat completed retries as no-ops, and save status, timeline and audit changes atomically. See [status conflict and retry behavior](docs/status-triage.md).

- **Case evidence picker:** search preserved real events, review them and link relevant evidence to an active case with an attributed rationale. See [case evidence association](docs/case-evidence-picker.md).

- **Assignment handoff:** owner changes create an in-app notification, with atomic persistence, harmless retries, and stale-owner checks from the case page. See [assignment and inbox behavior](docs/assignment-handoff.md).

- **Analyst event escalation:** review preserved real evidence and open a case with an attributed investigation reason. Repeated workspace submissions reuse the existing case. See [event-to-case workflow](docs/event-escalation.md).

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

## Interface and demonstration

- **Unified workspace:** a shared navigation rail, redesigned login, responsive tables/forms, case workspaces, approvals, reports and terminal. Login opens the operations overview. See [UI design and verification](docs/UI_DESIGN.md).
- **Light/dark mode:** use the top-right **Dark / Light** switch on the login page or workspace header. Initially follows the system theme, then saves your explicit choice in this browser and synchronizes it across tabs. Printed reports remain light.
- **Continuous simulated stream:** in **Training lab**, a named Tier 2+ analyst can select **10, 30 or 60 seconds** and click **Start simulated stream**. Each batch generates authentication-failure events using the current enabled rule threshold, a detection and one explicitly simulated case. It repeats this scenario; it does not generate varied real attacks.
- Keep the Training lab tab open. Use its links to inspect simulated evidence/cases in another tab and refresh those views to see new records. **Stop stream** prevents future batches; an in-flight batch may finish. Generation stops on errors, page departure or after 15 minutes. Background tab throttling may slow it. Saved records remain after stopping.

### Suggested project demonstration

1. Sign in and switch between light and dark mode.
2. Open **Training lab**, select a batch interval and start the stream.
3. Open a generated investigation; inspect its simulated evidence and detection.
4. Assign the case, add analyst notes, review risk and progress its permitted status.
5. Run an explicit **safe playbook preview** and inspect saved DRY_RUN results. The stream itself does not execute playbooks or response actions.
6. Open the case handoff report and demonstrate print/PDF and JSON export.
7. Stop the stream and show the separate **Intelligence** inventory and **Feed health** history.

Simulation is excluded from default real-case metrics. Continuous real alerts require an authenticated sensor/log source; external IP blocklists do not manufacture observed attacks. See [training workflow](docs/simulated-incident-lifecycle.md).

## Architecture

| Layer | Main components |
| --- | --- |
| Web interface | PHP pages including `dashboard.php`, `incidents.php`, and `control_plane/index.php` |
| API | `api/v1/` endpoints for alerts, incidents, IOCs, risk, playbooks, approvals and notifications |
| Backend | PHP services under `includes/soar/`, plus existing SIEM ingestion scripts |
| Data | MariaDB: legacy SIEM tables, incident/correlation records, playbook runs, approvals and audit history |
| Local environment | Docker Compose with Apache/PHP and MariaDB |

## Run locally with Docker

Requirements: Git and Docker Engine/Desktop with the Compose plugin, using Linux containers. Commands below use the stable Compose project name `blue-team-main`; keep it consistent when updating or moving folders. If you already use another project name, keep that existing name to retain its database volume.

1. Clone the project:

   ```bash
   git -c core.autocrlf=false clone https://github.com/RISHII-BHARADHWAJ/Blue-Team.git Blue-Team-git
   cd Blue-Team-git
   git config core.autocrlf false
   ```

2. Start the local development stack:

   ```bash
   docker compose -p blue-team-main up -d --build
   ```

3. Open **http://localhost:8080/** and sign in using your configured local development account. Useful pages:

   - SOC overview: `/soc.php`
   - Event evidence: `/events.php`
   - Telemetry source activity: `/sources.php`
   - Feed health and collection history: `/feeds.php`
   - Detection findings and rule settings: `/detections.php`
   - SIEM dashboard: `/dashboard.php`
   - Incident queue: `/incidents.php`
   - Report a case: `/incident-new.php` (named Tier 2+ analysts)
   - Printable handoff/JSON report: follow the Case handoff link inside a case
   - Indicator discovery/saved intelligence: follow the Case indicators link inside a case
   - Risk explanation/history: follow the risk link inside a case
   - Playbook previews/run history: follow the SOAR workflows link inside a case
   - Simulated walkthrough: `/demo.php`
   - Personal notifications: `/notifications.php`
   - SOAR control plane: `/control_plane/index.php`

4. Stop the stack without deleting the database:

   ```bash
   docker compose -p blue-team-main down
   ```

**Database initialization:** For a **new** MariaDB volume, Compose loads `database.sql`, `database/bootstrap/01_siem_tables.sql`, and SOAR migrations `001` through `006`, then migrations `007` (threat intelligence), `008` (event evidence), `009` (detection rules), `010` (feed collection history), `011` (simulated incidents), `012` (saved playbook previews), and `013` (manual case submission identity), in order. MariaDB initialization scripts **do not run again** for an existing volume. Back up existing data and use a reviewed migration process when upgrading. **Do not delete an existing volume to force migrations.**

**Credentials:** The repository contains development-oriented database and seeded-account settings. Treat them as unsafe defaults: replace passwords/secrets and secure or disable seeded demo accounts before connecting this project to a real network. Do not expose this local stack directly to the internet.

## Updating and checking an existing installation

Run from your Git clone, preserving local configuration:

```powershell
git switch main
git pull --ff-only origin main
docker compose -p blue-team-main up -d --build
docker compose -p blue-team-main ps
docker compose -p blue-team-main exec -T web php database/verify_schema.php
```

Refresh the browser with **Ctrl+Shift+R**. The redesign, continuous stream and theme switch introduce no new migrations, but earlier backend features require the schema through **013**. Rebuilding containers does not migrate an existing database. A healthy database container only establishes server availability, not the presence of application tables. If the verifier reports missing structures, back up the database and follow the migration guides below in numeric order. Keep the existing volume; do not re-import the base schema over your data.

A downloaded ZIP is not a Git clone: `git pull` will report “not a git repository.” Clone as above, preserve any local `.env`, stop the old stack and use its same Compose project name when starting the clone. Merely downloading a new ZIP or merging a PR does not update your running files.

### Windows startup troubleshooting

If the web container exits with `exec: /start.sh: not found` after cloning on Windows, check for CRLF line endings in Linux scripts. From the clone, normalize them and rebuild:

```powershell
git config core.autocrlf false
foreach ($file in @("deploy/start.sh", "deploy/run-ingestion.sh", "deploy/crontab")) {
    $path = Join-Path (Get-Location) $file
    $text = [System.IO.File]::ReadAllText($path).Replace("`r`n", "`n")
    [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
}
docker compose -p blue-team-main up -d --build --force-recreate web
docker compose -p blue-team-main logs --tail=30 web
```

Open **http://localhost:8080**, including port 8080. A “Started” message does not prove the process stayed running; inspect `docker compose -p blue-team-main ps` and the web logs if the browser refuses the connection. These steps preserve the database volume.

## Alternative manual setup (not the primary project workflow)

For local development without Compose:

1. Set up PHP 8.2, Apache and MariaDB 10.5, then copy the project into your web root.
2. Create a database named `cybertech_db`.
3. Import `database.sql`, then `database/bootstrap/01_siem_tables.sql`, followed by `database/migrations/001_create_soar_schema.sql` through `013_manual_case_requests.sql` **in numeric order** for a new database.
4. Configure the application's database connection (`includes/db.php` and environment/configuration used by the scripts) for your local database. Use non-demo credentials.
5. Open the application through your local web server. Configure scheduled ingestion only after checking feed/network requirements and logging:

   ```cron
   * * * * * php /path/to/project/feodo_realtime.php --scheduled >> /var/log/feodo_realtime.log 2>&1
   * * * * * php /path/to/project/api_fetch.php --scheduled >> /var/log/threat_fetch.log 2>&1
   ```

These schedules are examples, not a requirement for exploring the built-in SOAR workflows.

## Threat intelligence inventory

After migration `007`, Feodo Tracker indicators are stored in `threat_feed_indicators` and displayed at `/threat-intel.php`. These are externally reported indicators, **not** confirmed attacks against your environment. The bulk collector now imports Emerging Threats, CINS Army and Blocklist.de IP reputation lists into the same inventory without fabricating incident events. ThreatFox requires a separate API authentication key and is not automatically queried without one. Historical rows in `logs` are preserved; they are not automatically reclassified.

For an existing local database volume, back up the database first, then apply `database/migrations/007_threat_feed_indicators.sql` using your normal MariaDB migration workflow. Compose only auto-initializes **new** volumes. Do not delete an existing volume to force this migration.

For migration 008 on an existing installation, follow the [non-destructive evidence upgrade instructions](docs/event-evidence.md#upgrade-an-existing-installation) then the [migration 009 detection upgrade](docs/detection-rules.md#upgrade-existing-volumes) before submitting new alerts. Apply [migration 010](docs/feed-collection.md#upgrade-existing-installations) before running the updated feed collectors. Apply [migration 011](docs/simulated-incident-lifecycle.md#existing-database-upgrade) before using simulated incidents or the risk workspace. Apply [migration 012](docs/incident-playbook-workspace.md#upgrade-existing-installations) before using saved playbook previews. Apply [migration 013](docs/manual-case-intake.md#upgrade-existing-installations) before using manual case intake.

### Automatic collection and interpreting counts

Docker starts the collector scheduler. It checks every minute; Feodo defaults to a 300-second interval and the other three providers to 1,800 seconds. Administrators can enable sources and change intervals in **Feed health**. Collection continues while the web container runs, unless `FEED_COLLECTION_ENABLED=0` pauses it.

Manual diagnostics (not required on every refresh):

```powershell
docker compose -p blue-team-main exec -T web php feodo_realtime.php
docker compose -p blue-team-main exec -T web php api_fetch.php
```

- `SUCCESS`: the valid response was committed completely.
- `inserted: 0`: accepted indicators were already present; this is not a failure.
- `PARTIAL`: some rows were omitted; inspect the invalid count and cap flag in Feed health. Limits are 300 distinct Feodo IPs and 2,000 per plaintext provider per run.
- A provider may return a small or unchanged list. Faster polling does not guarantee new indicators or new sensor alerts.

Confirm background scheduling by checking that **Last attempt** advances after the configured interval. Manual success alone does not prove that cron is running. See [feed scheduling, outcomes and limits](docs/feed-collection.md).

## SIEM alert and threat-intelligence correlation

When an authenticated security sensor submits a valid event to `POST /api/v1/alerts.php`, the existing SIEM-to-SOAR pipeline stores the event and evaluates incident correlation. The response now includes `threat_intelligence.matched` and the matching public-feed records, if the alert's source IP is listed in `threat_feed_indicators`.

Open `/incidents.php?id=<incident ID>` to see the same source-IP reputation context alongside linked SIEM evidence. This lookup is read-only and reflects the **current** inventory; it is not a historical reputation snapshot. Duplicate alerts are still suppressed, and matching a feed cannot automatically trigger containment or alter incident severity.

The backend checks for migration 007 and works without it, returning no matches on older local databases. Data from external blocklists must never be interpreted as proof of activity against this environment.

## Testing and development

The [GitHub Actions workflow](https://github.com/RISHII-BHARADHWAJ/Blue-Team/actions) runs four jobs:

1. PHP syntax checks.
2. Disposable Docker Compose database and HTTP smoke tests.
3. Database-backed SOAR regression suites, including authorization and retry behavior.
4. Chromium desktop/mobile acceptance: 22 authenticated routes, login, case intake, simulated-stream start/stop, theme persistence/system preference, and report PDF generation.

Browser runs publish screenshots, a report PDF and results as the `visual-acceptance` artifact. Tests use a disposable database and explicitly synthetic fixtures; do not run fixture-heavy integration suites against your retained demo database.

## Completion and remaining scope

The requested local-demo feature set is implemented. Future work should focus on defects and deployment acceptance, rather than an open-ended feature backlog. The existing installation’s schema verifier was reported as **53 passed, 0 failed** after upgrade; that is not evidence that every workflow or subsequent installation is working. Complete the [local acceptance checklist](docs/v1-acceptance.md) before declaring a specific deployment or tagged release finished.

Production secrets/account provisioning, TLS and deployment hardening, independently managed sensor identities, backup/restore operations, retention/archival, monitoring, and live endpoint response integrations remain outside the lab scope. The investigative terminal is simulated, and the application does not implement live firewall blocking, endpoint isolation or account disabling. External feed and map availability depend on their providers. Passing CI is not a production security certification.

## Documentation

- [Database architecture and migrations](docs/soar/database.md)
- [Alert ingestion and normalization](docs/soar/alert-ingestion.md)
- [Incident management and correlation](docs/soar/incident-management.md)
- [Analyst case notes and attribution](docs/case-notes.md)
- [Searchable investigation history](docs/incident-timeline.md)
- [IOC enrichment](docs/soar/ioc-enrichment.md)
- [Risk scoring](docs/soar/risk-scoring.md)
- [Playbook engine and dry-run behavior](docs/soar/playbook-engine.md)
- [Approval control plane](docs/soar/approval-control-plane.md)

Some phase-specific design documents describe their original implementation phase; check the code and current tests for subsequent integrations and hardening.
