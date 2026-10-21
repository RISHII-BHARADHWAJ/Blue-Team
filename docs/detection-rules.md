# Configurable detections

Open `/detections.php` to review findings. All authenticated analyst tiers can read
findings; named administrators can change enabled status, severity and window.
Authentication thresholds accept 2–100 failures; windows accept 60–86400 seconds.
Updates require session CSRF, recheck the user's current database role, reject
stale revisions, and atomically record before/after settings in the audit log.

## Upgrade existing volumes

Back up your database, apply migrations through 008 first, then run this from the
repository directory in PowerShell or a Unix shell. Do not delete the data volume.
Pause sensor submission during the application/schema upgrade.

```sh
docker compose cp database/migrations/009_detection_rules.sql db:/tmp/009_detection_rules.sql
docker compose exec -T db sh -c 'mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" < /tmp/009_detection_rules.sql'
docker compose up -d --build
```

Migration 009 adds four tables and seeds two enabled rules. It is rerunnable and
preserves existing settings and findings. Fresh Compose databases mount it
automatically. Apply manually on embedded or other existing deployments too.
The updated ingestion path requires migration 009; missing storage fails the
transaction rather than accepting events without evaluating rules.

## Rules and evidence contract

- **Repeated authentication failures:** defaults to 5 failures in 300 seconds,
  severity HIGH. The submitted metadata must contain the exact strings
  `event_type: authentication` and `outcome: failure`, and a valid `source_ip`.
  Message text and category alone never establish an authentication failure.
- **Source IP intelligence:** defaults to severity MEDIUM and a 3600-second
  cooldown. Matches the canonical source IP against stored external feed entries.
  Saves provider, classification and available feed timestamps with the finding.
  A listing is reputation context, not proof of a local attack. No freshness cutoff
  is enforced; administrators should inspect collection timestamps.

Example sensor submission to the existing authenticated `POST /api/v1/alerts.php`:

```json
{
  "source": "lab-ssh-sensor",
  "source_type": "sensor",
  "source_event_id": "unique-failure-0001",
  "source_ip": "192.0.2.40",
  "severity": "LOW",
  "category": "SSH",
  "message": "Authentication rejected",
  "is_simulated": true,
  "metadata": {"event_type": "authentication", "outcome": "failure"}
}
```

Send distinct source event IDs for distinct events. Retries suppressed by ingestion
do not count twice. Change the example ID for each new test event. The example
is simulated and cannot create a real incident. Successful ingestion includes a
`detections` array of newly emitted findings; duplicate/invalid results keep their
existing response contract and do not evaluate rules.

## Window, concurrency and correlation semantics

Grouping uses authenticated submitter, claimed source, source type, canonical source
IP and simulation flag. The shared bearer credential is still not a unique sensor
identity. Source labels remain claims. Groups do not span sensors or simulation
boundaries. Counting is based on server UTC receipt time in `(now-window, now]`;
source timestamps, including old or future timestamps, do not change the window.

A finding stores the latest threshold-sized set of supporting events, not the full
count in the window. Authentication observations received while disabled are
retained and may count after re-enabling. Existing historical evidence is not
backfilled or rescanned. Configuration changes take effect on new accepted events;
a new revision starts a new cooldown, so it can generate a fresh finding.

For each group and rule revision, at most one finding is emitted per window.
The rule window also serves as cooldown. After expiry, a new event can trigger a
new finding if its current window meets the rule. Rule rows are locked in fixed
order before ingestion, making concurrent submissions/configuration changes
serializable for this evaluation. This deliberately serializes ingestion and is
suited to the current small deployment, not a high-throughput distributed SIEM.

Original logs and canonical evidence retain the submitted severity. New findings
may raise (never lower) the severity of a separate copy passed to existing incident
correlation. HIGH/CRITICAL findings can therefore open a case for a LOW sensor
submission; MEDIUM intelligence findings may remain standalone. Findings link to
the incident returned by correlation, and all supporting events remain reachable
from the finding. The trigger event is the one attached to the case. The existing
correlation policy still applies to all accepted real alerts even if rules are
disabled; disabling a rule does not disable severity-based correlation.

Simulated findings have an explicit flag, separate count/cooldown groups and no
incident link. They never enter real correlation. No rule starts a playbook or
performs containment. The full simulated incident lifecycle remains separate work.

Evidence, observation, finding, links, deduplication and correlation share one
transaction/savepoint. Failed processing rolls all of them back. Stored findings
retain the settings and intelligence context used at detection time, independent
of later rule changes or feed updates. The append-only evidence projection grows
with stored evidence; archival/retention tooling is not part of this milestone.

## Validation

CI covers thresholds, successful-auth exclusion, receipt-time windows, sensor and
simulation separation, duplicate retries, cooldown, configuration permissions and
revisions, evidence snapshots, intelligence attribution, rollback/retry and HTTP
CSRF/access/escaping. Existing SOAR and evidence suites run unchanged. Local PHP and
Docker are unavailable in the Work environment; rely on the PR's reported CI
results, not an assumed local run. Interactive browser and Windows-localhost checks
are still needed before treating this as a validated release on your installation.
