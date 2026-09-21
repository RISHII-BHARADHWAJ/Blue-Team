<?php
/**
 * ThreatPulse SOAR - Risk Scoring Engine
 * 
 * Central orchestrator for incident risk scoring and priority calculation:
 * 1. Aggregates incident telemetry, attached alerts, and enriched IOC evidence
 * 2. Runs deterministic calculation via RiskScoreCalculator
 * 3. Persists full explainable factor breakdown to `risk_assessments`
 * 4. Updates incident risk_score and priority fields in database
 * 5. Emits timeline milestones on meaningful score shifts (>= 10 points or priority change)
 * 6. Generates security audit log entries
 */

require_once __DIR__ . '/RiskPolicy.php';
require_once __DIR__ . '/RiskFactor.php';
require_once __DIR__ . '/RiskAssessment.php';
require_once __DIR__ . '/RiskScoreCalculator.php';
require_once __DIR__ . '/../IncidentRepository.php';
require_once __DIR__ . '/../IncidentTimeline.php';
require_once __DIR__ . '/../IocRepository.php';

class RiskScoringEngine {
    private ?PDO $pdo;
    private IncidentRepository $incRepo;
    private IncidentTimeline $timeline;
    private IocRepository $iocRepo;
    private RiskScoreCalculator $calculator;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
        $this->incRepo = new IncidentRepository($pdo);
        $this->timeline = new IncidentTimeline($pdo);
        $this->iocRepo = new IocRepository($pdo);
        $this->calculator = new RiskScoreCalculator();
    }

    /**
     * Recalculate risk score and priority for a specific incident.
     * 
     * @param int $incidentId Target incident ID
     * @param string $actor Submitting identity ('system', analyst username)
     * @param array $assetMetadata Optional asset inventory context
     * @return RiskAssessment Complete calculated assessment
     */
    public function recalculateIncident(
        int $incidentId,
        string $actor = 'system',
        array $assetMetadata = []
    ): RiskAssessment {
        $incident = $this->incRepo->find($incidentId, true);
        if (!$incident) {
            throw new InvalidArgumentException("Incident #{$incidentId} does not exist.");
        }

        // 1. Fetch attached alerts
        $alerts = $this->incRepo->getAttachedAlerts($incidentId);

        // 2. Fetch attached IOCs and their enrichment data
        $iocs = $this->iocRepo->getIncidentIocs($incidentId);
        foreach ($iocs as &$ioc) {
            $enrichments = $this->iocRepo->getIocEnrichments((int)$ioc['ioc_id']);
            $ioc['providers'] = [];
            foreach ($enrichments as $enr) {
                $ioc['providers'][$enr['provider']] = [
                    'status'     => $enr['status'],
                    'reputation' => $enr['parsed_summary']['reputation'] ?? 0,
                    'confidence' => $enr['parsed_summary']['confidence'] ?? 50,
                ];
            }
        }

        // 3. Compute Risk Assessment
        $assessment = $this->calculator->calculate($incident, $alerts, $iocs, $assetMetadata);

        $oldScore = (int)($incident['risk_score'] ?? 0);
        $oldPriority = $incident['priority'] ?? 'P3';
        $newScore = $assessment->score;
        $newPriority = $assessment->priority;

        $inTx = $this->pdo && $this->pdo->inTransaction();
        if ($this->pdo && !$inTx) {
            $this->pdo->beginTransaction();
        }

        try {
            // 4. Persist to risk_assessments history table
            if ($this->pdo) {
                $factorsJson = json_encode(
                    array_map(fn($f) => $f->toArray(), $assessment->factors),
                    JSON_UNESCAPED_SLASHES
                );

                $stmt = $this->pdo->prepare("
                    INSERT INTO risk_assessments (
                        incident_id, score, priority, confidence, factor_breakdown, 
                        policy_version, calculated_at, calculated_by
                    ) VALUES (?, ?, ?, ?, ?, ?, NOW(), ?)
                ");
                $stmt->execute([
                    $incidentId,
                    $newScore,
                    $newPriority,
                    $assessment->confidence,
                    $factorsJson,
                    RiskPolicy::VERSION,
                    $actor
                ]);

                // 5. Update incident record
                $this->incRepo->update($incidentId, [
                    'risk_score' => $newScore,
                    'priority'   => $newPriority,
                ]);
            }

            // 6. Check for Meaningful Shift (>= 10 pts change or priority change)
            $scoreDiff = abs($newScore - $oldScore);
            $priorityChanged = ($oldPriority !== $newPriority);

            if ($scoreDiff >= 10 || $priorityChanged) {
                $this->timeline->addEvent(
                    $incidentId,
                    'STATUS_CHANGE',
                    $actor === 'system' ? IncidentTimeline::ACTOR_SYSTEM : IncidentTimeline::ACTOR_ANALYST,
                    $actor,
                    "Risk score recalculated: {$oldScore} ({$oldPriority}) -> {$newScore} ({$newPriority})",
                    [
                        'event_subtype' => 'RISK_SCORE_CHANGED',
                        'old_score'     => $oldScore,
                        'new_score'     => $newScore,
                        'old_priority'  => $oldPriority,
                        'new_priority'  => $newPriority,
                        'confidence'    => $assessment->confidence,
                        'diff'          => $scoreDiff
                    ]
                );
            }

            // 7. Security Audit Log
            $this->auditLog($actor, 'recalculate_risk', $incident['incident_number'], 'success', [
                'incident_id'  => $incidentId,
                'score'        => $newScore,
                'priority'     => $newPriority,
                'confidence'   => $assessment->confidence,
                'score_change' => "{$oldScore} -> {$newScore}"
            ]);

            if ($this->pdo && !$inTx) {
                $this->pdo->commit();
            }

            return $assessment;

        } catch (Exception $e) {
            if ($this->pdo && !$inTx && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Retrieve complete risk scoring history for an incident.
     */
    public function getRiskHistory(int $incidentId): array {
        if (!$this->pdo) return [];

        $stmt = $this->pdo->prepare("
            SELECT * FROM risk_assessments 
            WHERE incident_id = ? 
            ORDER BY calculated_at DESC
        ");
        $stmt->execute([$incidentId]);
        $rows = $stmt->fetchAll();

        foreach ($rows as &$row) {
            if (!empty($row['factor_breakdown']) && is_string($row['factor_breakdown'])) {
                $row['factor_breakdown'] = json_decode($row['factor_breakdown'], true) ?: $row['factor_breakdown'];
            }
        }

        return $rows;
    }

    /**
     * Retrieve the most recent risk assessment for an incident.
     */
    public function getLatestAssessment(int $incidentId): ?array {
        if (!$this->pdo) return null;

        $stmt = $this->pdo->prepare("
            SELECT * FROM risk_assessments 
            WHERE incident_id = ? 
            ORDER BY calculated_at DESC 
            LIMIT 1
        ");
        $stmt->execute([$incidentId]);
        $row = $stmt->fetch();
        if (!$row) return null;

        if (!empty($row['factor_breakdown']) && is_string($row['factor_breakdown'])) {
            $row['factor_breakdown'] = json_decode($row['factor_breakdown'], true) ?: $row['factor_breakdown'];
        }

        return $row;
    }

    /**
     * Security audit logging.
     */
    private function auditLog(string $analyst, string $action, string $target, string $result, array $details): void {
        if (!$this->pdo) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-Risk-Engine/1.0';

        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                substr($analyst, 0, 50),
                substr($ip, 0, 45),
                substr($action, 0, 100),
                substr($target, 0, 255),
                $result,
                substr(json_encode($details, JSON_UNESCAPED_SLASHES), 0, 1000),
                substr($ua, 0, 500)
            ]);
        } catch (Exception $e) {}
    }
}
