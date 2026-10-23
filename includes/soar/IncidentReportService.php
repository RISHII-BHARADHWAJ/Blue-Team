<?php
/** Read-only incident handoff snapshot. No enrichment, execution or evidence mutation. */
declare(strict_types=1);
final class IncidentReportService
{
    public const SCHEMA_VERSION = 'threatpulse.incident-report.v1';
    public const SECTION_LIMIT = 100;
    public const TEXT_LIMIT = 10000;

    public function __construct(private PDO $pdo) {}

    public function build(int $incidentId): array
    {
        if ($incidentId < 1) throw new InvalidArgumentException('Select a valid incident.');
        $own = !$this->pdo->inTransaction();
        if ($own) {
            // A single request sees one committed view across counts and all section queries.
            $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
            $this->pdo->beginTransaction();
        }
        try {
            $stmt = $this->pdo->prepare('SELECT i.id, i.incident_number, i.title,
                LEFT(i.description,10000) AS description, CHAR_LENGTH(i.description)>10000 AS description_truncated,
                i.status, i.severity, i.priority, i.risk_score, i.is_simulated, i.attack_category,
                i.mitre_tactics, i.mitre_techniques, i.assigned_to, u.username AS assigned_analyst,
                i.lead_analyst, lead_user.username AS lead_analyst_name, i.created_at, i.updated_at,
                i.contained_at, i.resolved_at, i.closed_at
                FROM incidents i LEFT JOIN users u ON u.id=i.assigned_to LEFT JOIN users lead_user ON lead_user.id=i.lead_analyst
                WHERE i.id=?');
            $stmt->execute([$incidentId]); $case = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$case) throw new OutOfBoundsException('Incident not found.');
            $case['is_simulated'] = (bool)$case['is_simulated'];
            $case['description_truncated'] = (bool)$case['description_truncated'];
            $generatedAt = $this->pdo->query("SELECT DATE_FORMAT(UTC_TIMESTAMP(),'%Y-%m-%dT%H:%i:%sZ')")->fetchColumn();
            $reportTime = $this->pdo->quote((string)$this->pdo->query('SELECT NOW()')->fetchColumn());
            $sections = [];
            $sections['alerts'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM incident_alerts WHERE incident_id=?',
                'SELECT l.id AS log_id, l.source_ip, l.severity, l.category, LEFT(l.message,10000) AS message,
                    CHAR_LENGTH(l.message)>10000 AS text_truncated, l.timestamp AS event_timestamp,
                    ia.correlation_rule, ia.added_at AS attached_at, e.id AS evidence_id, e.source,
                    e.source_type, e.source_event_id, e.submitted_by, e.received_at, e.timestamp_origin,
                    e.payload_sha256, e.is_simulated AS evidence_is_simulated
                    FROM incident_alerts ia JOIN logs l ON l.id=ia.log_id LEFT JOIN event_evidence e ON e.log_id=l.id
                    WHERE ia.incident_id=? ORDER BY l.timestamp DESC,l.id DESC LIMIT ?', 'Newest event first');
            $sections['notes'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM case_notes WHERE incident_id=?',
                'SELECT n.id, n.author_id, u.username AS author, LEFT(n.note_text,10000) AS note_text,
                    CHAR_LENGTH(n.note_text)>10000 AS text_truncated, n.is_pinned, n.created_at, n.updated_at
                    FROM case_notes n LEFT JOIN users u ON u.id=n.author_id WHERE n.incident_id=?
                    ORDER BY n.is_pinned DESC,n.created_at DESC,n.id DESC LIMIT ?', 'Pinned notes first, then newest');
            $sections['indicators'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM incident_iocs WHERE incident_id=?',
                'SELECT i.id, i.ioc_type, i.ioc_value, ii.role, ii.discovered_at, i.source_feed
                    FROM incident_iocs ii JOIN iocs i ON i.id=ii.ioc_id WHERE ii.incident_id=?
                    ORDER BY ii.discovered_at DESC,ii.id DESC LIMIT ?', 'Newest case link first');
            $sections['evidence'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM evidence WHERE incident_id=?',
                'SELECT e.id, e.evidence_type, e.title, e.data_hash, e.collected_by, u.username AS collector, e.collected_at
                    FROM evidence e LEFT JOIN users u ON u.id=e.collected_by WHERE e.incident_id=?
                    ORDER BY e.collected_at DESC,e.id DESC LIMIT ?', 'Newest collection first');
            $sections['playbook_runs'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM playbook_runs WHERE incident_id=?',
                "SELECT r.id, r.playbook_id, r.playbook_version, r.status, r.current_step_order, r.analyst_id,
                    u.username AS analyst, r.started_at, r.completed_at,
                    CASE WHEN JSON_TYPE(JSON_EXTRACT(r.execution_context,'$.definition_snapshot.playbook.display_name'))='STRING'
                        THEN JSON_UNQUOTE(JSON_EXTRACT(r.execution_context,'$.definition_snapshot.playbook.display_name')) ELSE p.display_name END AS playbook_name,
                    CASE WHEN JSON_TYPE(JSON_EXTRACT(r.execution_context,'$.definition_snapshot.playbook.display_name'))='STRING'
                        THEN 'SAVED_SNAPSHOT' ELSE 'CURRENT_CATALOG' END AS name_source,
                    JSON_UNQUOTE(JSON_EXTRACT(r.execution_context,'$.mode')) AS stored_mode,
                    JSON_UNQUOTE(JSON_EXTRACT(r.execution_context,'$.dry_run')) AS stored_dry_run
                    FROM playbook_runs r JOIN playbooks p ON p.id=r.playbook_id LEFT JOIN users u ON u.id=r.analyst_id
                    WHERE r.incident_id=? ORDER BY r.started_at DESC,r.id DESC LIMIT ?", 'Newest run first');
            foreach ($sections['playbook_runs']['rows'] as &$run) {
                $mode = $run['stored_mode'];
                $run['mode'] = $mode === 'DRY_RUN' || $run['stored_dry_run'] === 'true' ? 'DRY_RUN' :
                    (in_array($mode,['MANUAL','AUTOMATIC'],true) ? $mode : 'UNKNOWN');
                unset($run['stored_mode'],$run['stored_dry_run']);
            }
            unset($run);
            $sections['approvals'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM approval_requests a JOIN playbook_runs r ON r.id=a.playbook_run_id AND r.incident_id=a.incident_id WHERE a.incident_id=?',
                "SELECT a.id, a.playbook_run_id, a.action_name, a.required_tier, a.status AS stored_status,
                    CASE WHEN a.status='PENDING' AND a.expires_at<={$reportTime} THEN 'EXPIRED_BY_TIME' ELSE a.status END AS effective_status,
                    a.requested_at, a.expires_at, a.reviewed_by, u.username AS reviewer, a.reviewed_at, a.decided_at
                    FROM approval_requests a JOIN playbook_runs r ON r.id=a.playbook_run_id AND r.incident_id=a.incident_id
                    LEFT JOIN users u ON u.id=a.reviewed_by WHERE a.incident_id=? ORDER BY a.requested_at DESC,a.id DESC LIMIT ?", 'Newest request first');
            $sections['response_actions'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM response_actions WHERE incident_id=?',
                'SELECT id, playbook_run_id, approval_id, action_type, target_entity, status, dispatched_at,
                    executed_at, rollback_supported, is_rolled_back FROM response_actions WHERE incident_id=?
                    ORDER BY dispatched_at DESC,id DESC LIMIT ?', 'Newest dispatch first');
            $sections['timeline'] = $this->section($incidentId,
                'SELECT COUNT(*) FROM incident_timeline WHERE incident_id=?',
                'SELECT id, event_type, actor_type, actor_name, summary, created_at FROM incident_timeline
                    WHERE incident_id=? ORDER BY created_at DESC,id DESC LIMIT ?', 'Newest milestone first');
            $stmt = $this->pdo->prepare('SELECT id,score,priority,confidence,policy_version,calculated_at,calculated_by
                FROM risk_assessments WHERE incident_id=? ORDER BY calculated_at DESC,id DESC LIMIT 1');
            $stmt->execute([$incidentId]); $risk = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
            $partial = $case['description_truncated'];
            foreach ($sections as $section) $partial = $partial || $section['truncated'] || $section['text_truncated_count']>0;
            $report = [
                'schema_version'=>self::SCHEMA_VERSION, 'generated_at_utc'=>$generatedAt,
                'record_time_basis'=>'Database/server time unless a field explicitly says UTC',
                'simulation_label'=>$case['is_simulated'] ? 'SIMULATED TEST DATA' : 'OBSERVED CASE',
                'partial'=>$partial, 'incident'=>$case, 'latest_risk_assessment'=>$risk, 'sections'=>$sections,
                'limitations'=>[
                    'A generated handoff summary, not a full database or forensic evidence export. Regeneration may produce different data.',
                    'At most 100 rows per section; text fields are capped at 10,000 characters. Counts and truncation flags disclose omitted records or text.',
                    'Risk is the latest saved assessment, not recalculated. Missing assessment does not establish low risk.',
                    'Indicators are linked candidates with inferred roles; no current provider verdict is asserted by this report.',
                    'Completed dry-run playbooks are previews. Stored case, approval and response statuses do not independently verify external containment.',
                    'Raw event/provider payloads, evidence contents and file paths, approval payloads, playbook parameters/results and timeline details are omitted.',
                    'Included analyst notes and alert summaries may contain sensitive information; review before sharing.',
                ],
            ];
            if ($own) $this->pdo->commit();
            return $report;
        } catch (Throwable $e) {
            if ($own && $this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }

    private function section(int $incidentId, string $countSql, string $rowsSql, string $order): array
    {
        $stmt = $this->pdo->prepare($countSql); $stmt->execute([$incidentId]); $total = (int)$stmt->fetchColumn();
        $stmt = $this->pdo->prepare($rowsSql); $stmt->bindValue(1,$incidentId,PDO::PARAM_INT);
        $stmt->bindValue(2,self::SECTION_LIMIT,PDO::PARAM_INT); $stmt->execute(); $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $textTruncated = 0;
        foreach ($rows as &$row) {
            if (array_key_exists('text_truncated',$row)) { $row['text_truncated']=(bool)$row['text_truncated']; $textTruncated += $row['text_truncated'] ? 1 : 0; }
        }
        unset($row);
        return ['total'=>$total,'included'=>count($rows),'limit'=>self::SECTION_LIMIT,
            'truncated'=>$total>count($rows),'text_truncated_count'=>$textTruncated,'order'=>$order,'rows'=>$rows];
    }

    public static function json(array $report): string
    {
        return json_encode($report,JSON_THROW_ON_ERROR|JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)."\n";
    }
}
