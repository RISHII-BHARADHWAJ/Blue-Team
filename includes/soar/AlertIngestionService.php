<?php
/**
 * ThreatPulse SOAR - Alert Ingestion Service
 * 
 * Central coordinator for the SOAR Alert Ingestion & Normalization pipeline:
 * 1. Validates incoming payload
 * 2. Normalizes fields into canonical schema
 * 3. Calculates deterministic SHA-256 fingerprint
 * 4. Evaluates deduplication within time window
 * 5. Emits security audit record
 * 6. Returns structured ingestion contract
 * 
 * Strict non-goals: Does NOT create incidents, execute playbooks, or run response actions.
 */

require_once __DIR__ . '/AlertSchema.php';
require_once __DIR__ . '/AlertValidator.php';
require_once __DIR__ . '/AlertNormalizer.php';
require_once __DIR__ . '/AlertDeduplicator.php';
require_once __DIR__ . '/AlertRepository.php';

class AlertIngestionService {
    private AlertValidator $validator;
    private AlertNormalizer $normalizer;
    private AlertDeduplicator $deduplicator;
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->validator = new AlertValidator();
        $this->normalizer = new AlertNormalizer();
        $this->deduplicator = new AlertDeduplicator();
        $this->pdo = $pdo;
    }

    /**
     * Ingest and normalize a raw alert payload.
     * 
     * @param array $rawPayload Raw input array
     * @param string $actor Submitting identity (Analyst username, 'api_sensor', etc.)
     * @return array Structured ingestion result
     */
    public function ingest(array $rawPayload, string $actor = 'system'): array {
        // 1. Validate raw input
        $valResult = $this->validator->validate($rawPayload);
        if (!$valResult['valid']) {
            $this->auditLog($actor, 'alert_ingest', 'rejected_validation', 'failure', [
                'errors' => $valResult['errors']
            ]);

            return [
                'success'   => false,
                'status'    => 'validation_failed',
                'error'     => 'validation_failed',
                'fields'    => $valResult['errors'],
                'duplicate' => false,
            ];
        }

        // 2. Normalize into Canonical Alert Model
        try {
            $canonicalAlert = $this->normalizer->normalize($rawPayload);
        } catch (InvalidArgumentException $e) {
            $this->auditLog($actor, 'alert_ingest', 'rejected_normalization', 'failure', [
                'error' => $e->getMessage()
            ]);

            return [
                'success'   => false,
                'status'    => 'validation_failed',
                'error'     => 'validation_failed',
                'fields'    => [[
                    'field'   => 'event_timestamp',
                    'code'    => 'INVALID_TIMESTAMP',
                    'message' => $e->getMessage()
                ]],
                'duplicate' => false,
            ];
        }

        // 3. Generate Deterministic Fingerprint
        $fingerprint = $this->deduplicator->generateFingerprint($canonicalAlert);

        // 4. Perform Deduplication Check
        $dedupResult = $this->deduplicator->checkAndRegister($fingerprint, $this->pdo);

        if ($dedupResult['is_duplicate']) {
            $this->auditLog($actor, 'alert_ingest', 'duplicate_suppressed', 'success', [
                'fingerprint' => $fingerprint,
                'severity'    => $canonicalAlert->severity,
                'category'    => $canonicalAlert->category,
                'source_ip'   => $canonicalAlert->source_ip,
            ]);

            return [
                'success'     => true,
                'status'      => 'duplicate',
                'fingerprint' => $fingerprint,
                'duplicate'   => true,
                'alert'       => $canonicalAlert->toArray(),
                'message'     => $dedupResult['reason'],
            ];
        }

        // 5. Audit Log Successful Ingestion
        $this->auditLog($actor, 'alert_ingest', 'accepted', 'success', [
            'fingerprint' => $fingerprint,
            'severity'    => $canonicalAlert->severity,
            'category'    => $canonicalAlert->category,
            'source_ip'   => $canonicalAlert->source_ip,
            'source'      => $canonicalAlert->source,
        ]);

        return [
            'success'     => true,
            'status'      => 'accepted',
            'fingerprint' => $fingerprint,
            'duplicate'   => false,
            'alert'       => $canonicalAlert->toArray(),
        ];
    }

    /**
     * Legacy SIEM Bridge: Ingest and normalize a record directly from existing `logs` table.
     * Preserves original log without modification.
     * 
     * @param array $logRecord Row from `logs` table
     * @param string $actor Submitting identity
     * @return array Structured ingestion result
     */
    public function ingestLegacyLog(array $logRecord, string $actor = 'legacy_bridge'): array {
        $raw = [
            'source'          => 'threatpulse_siem_legacy',
            'source_type'     => 'log',
            'source_event_id' => isset($logRecord['id']) ? (string)$logRecord['id'] : null,
            'source_ip'       => $logRecord['source_ip'] ?? null,
            'severity'        => $logRecord['severity'] ?? 'INFO',
            'category'        => $logRecord['category'] ?? 'Other',
            'message'         => $logRecord['message'] ?? '',
            'event_timestamp' => $logRecord['timestamp'] ?? null,
            'metadata'        => [
                'legacy_log_id' => $logRecord['id'] ?? null,
                'ingested_via'  => 'legacy_bridge'
            ]
        ];

        return $this->ingest($raw, $actor);
    }

    /**
     * Record security audit entry without exposing sensitive credentials.
     */
    private function auditLog(string $analyst, string $action, string $target, string $result, array $details): void {
        if (!$this->pdo) {
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-SOAR-Engine/1.0';
        $detailsJson = json_encode($details, JSON_UNESCAPED_SLASHES);

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
                $result === 'success' ? 'success' : ($result === 'failure' ? 'failure' : 'blocked'),
                substr($detailsJson, 0, 1000),
                substr($ua, 0, 500)
            ]);
        } catch (Exception $e) {
            // Non-blocking audit log catch
        }
    }
}
