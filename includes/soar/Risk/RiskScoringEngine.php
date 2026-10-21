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
require_once __DIR__ . '/../SoarAuth.php';

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
        array $assetMetadata = [],
        ?int $userId = null
    ): RiskAssessment {
        $own = $this->pdo && !$this->pdo->inTransaction();
        $savepoint = 'risk_' . bin2hex(random_bytes(8));
        if ($this->pdo) {
            if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $savepoint");
        }
        try {
            if ($userId !== null && $this->pdo) {
                $stmt = $this->pdo->prepare('SELECT username, role FROM users WHERE id = ?');
                $stmt->execute([$userId]); $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']), 'create_incidents')) {
                    throw new DomainException('Tier 2 or higher is required to recalculate risk.');
                }
                $actor = $user['username'];
            }
            $incident = $this->incRepo->find($incidentId, true);
            if (!$incident) throw new InvalidArgumentException("Incident #{$incidentId} does not exist.");
            $alerts = $this->incRepo->getAttachedAlerts($incidentId);
            // Destination is only available when it was actually reported in preserved evidence.
            if ($this->pdo) {
                $stmt = $this->pdo->prepare('SELECT e.log_id, e.canonical_json FROM event_evidence e
                    JOIN incident_alerts ia ON ia.log_id = e.log_id WHERE ia.incident_id = ?');
                $stmt->execute([$incidentId]); $evidence = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
                foreach ($alerts as &$alert) {
                    $canonical = json_decode($evidence[$alert['log_id']] ?? '{}', true) ?: [];
                    $alert['destination_ip'] = $canonical['destination_ip'] ?? null;
                }
                unset($alert);
            }
            $iocs = $this->currentIocEvidence($incidentId);
            $assessment = $this->calculator->calculate($incident, $alerts, $iocs, $assetMetadata);
            $assessment->calculated_by = $actor;
            $oldScore = (int)($incident['risk_score'] ?? 0);
            $oldPriority = $incident['priority'] ?? 'P3';
            $newScore = $assessment->score; $newPriority = $assessment->priority;

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
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $incidentId,
                    $newScore,
                    $newPriority,
                    $assessment->confidence,
                    $factorsJson,
                    RiskPolicy::VERSION,
                    $assessment->calculated_at,
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

            if ($this->pdo) {
                if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
            }

            return $assessment;

        } catch (Throwable $e) {
            if ($this->pdo && $this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint"); $this->pdo->exec("RELEASE SAVEPOINT $savepoint"); }
            }
            throw $e;
        }
    }

    /**
     * Retrieve complete risk scoring history for an incident.
     */
    public function getRiskHistory(int $incidentId, int $limit = 25, int $offset = 0): array {
        if (!$this->pdo) return [];

        $stmt = $this->pdo->prepare("
            SELECT * FROM risk_assessments 
            WHERE incident_id = ? 
            ORDER BY calculated_at DESC, id DESC LIMIT ? OFFSET ?
        ");
        $stmt->bindValue(1, $incidentId, PDO::PARAM_INT);
        $stmt->bindValue(2, max(1, min(100, $limit)), PDO::PARAM_INT);
        $stmt->bindValue(3, max(0, $offset), PDO::PARAM_INT);
        $stmt->execute();
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
            ORDER BY calculated_at DESC, id DESC
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

    /** Read-only snapshot with bounded history; absence is not a zero-risk assessment. */
    public function workspace(int $incidentId, int $page = 1, ?int $assessmentId = null): array {
        $incident = $this->incRepo->find($incidentId);
        if (!$incident) throw new InvalidArgumentException('Incident not found.');
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM risk_assessments WHERE incident_id = ?');
        $stmt->execute([$incidentId]); $total = (int)$stmt->fetchColumn();
        $pages = max(1, (int)ceil($total / 25)); $page = max(1, min($page, $pages));
        $latest = $this->getLatestAssessment($incidentId); $selected = $latest;
        if ($assessmentId !== null) {
            $stmt = $this->pdo->prepare('SELECT * FROM risk_assessments WHERE incident_id = ? AND id = ?');
            $stmt->execute([$incidentId, $assessmentId]); $selected = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$selected) throw new InvalidArgumentException('Assessment not found for this incident.');
            $selected['factor_breakdown'] = json_decode($selected['factor_breakdown'], true) ?: [];
        }
        return ['incident'=>$incident, 'incident_id'=>$incidentId, 'latest'=>$latest, 'selected'=>$selected,
            'history'=>$this->getRiskHistory($incidentId, 25, ($page - 1) * 25),
            'pagination'=>['page'=>$page, 'pages'=>$pages, 'total'=>$total, 'per_page'=>25]];
    }

    /** Latest row per IOC/provider only, unexpired and successful; never queries the network. */
    private function currentIocEvidence(int $incidentId): array {
        if (!$this->pdo) return [];
        $iocs = [];
        foreach ($this->iocRepo->getIncidentIocs($incidentId) as $ioc) {
            $iocId = (int)$ioc['ioc_id'];
            if (isset($iocs[$iocId])) continue; // Different incident roles are not distinct IOCs.
            $ioc['assessment'] = 'UNKNOWN'; $ioc['confidence_score'] = 0; $ioc['providers'] = [];
            $stmt = $this->pdo->prepare('SELECT e.provider, e.parsed_summary FROM enrichment_results e
                WHERE e.ioc_id = ? AND e.status = \'SUCCESS\' AND e.cached_until > UTC_TIMESTAMP()
                AND NOT EXISTS (SELECT 1 FROM enrichment_results newer WHERE newer.ioc_id = e.ioc_id
                    AND newer.provider = e.provider AND (newer.created_at > e.created_at
                    OR (newer.created_at = e.created_at AND newer.id > e.id)))');
            $stmt->execute([$iocId]);
            $malicious = false; $suspicious = false; $clean = false; $reports = 0;
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $summary = json_decode($row['parsed_summary'] ?? '{}', true) ?: [];
                if (!isset($summary['reputation'], $summary['confidence']) || !is_numeric($summary['reputation']) || !is_numeric($summary['confidence'])) continue;
                $reputation = max(0, min(100, (int)$summary['reputation']));
                $confidence = max(0, min(100, (int)$summary['confidence'])); $reports++;
                $ioc['providers'][$row['provider']] = ['status'=>'SUCCESS', 'reputation'=>$reputation, 'confidence'=>$confidence];
                if ($reputation >= 75) { $malicious = true; $ioc['confidence_score'] = max($ioc['confidence_score'], $confidence); }
                elseif ($reputation >= 25) $suspicious = true;
                elseif ($reputation === 0 && $confidence >= 80) $clean = true;
            }
            $ioc['assessment'] = $malicious && $clean ? 'CONFLICTING' : ($malicious ? 'MALICIOUS' : ($suspicious ? 'SUSPICIOUS' : ($reports ? 'BENIGN' : 'UNKNOWN')));
            $iocs[$iocId] = $ioc;
        }
        return array_values($iocs);
    }

    /**
     * Security audit logging.
     */
    private function auditLog(string $analyst, string $action, string $target, string $result, array $details): void {
        if (!$this->pdo) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-Risk-Engine/1.0';

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
    }
}
