<?php
/**
 * Durable bridge from HTTP alert ingestion to legacy SIEM logs and SOAR correlation.
 *
 * All database changes for a newly accepted alert share one transaction. This
 * ensures a 202 response never means "deduplicated but silently lost before
 * reaching the SIEM/incident pipeline".
 *
 * This service only records evidence and opens/attaches incidents. It never
 * starts a playbook or performs automated response/containment actions.
 */
declare(strict_types=1);

require_once __DIR__ . '/AlertIngestionService.php';
require_once __DIR__ . '/IncidentManager.php';

final class SiemSoarAlertPipeline
{
    private PDO $pdo;
    private AlertIngestionService $ingestion;
    private IncidentManager $incidents;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->ingestion = new AlertIngestionService($pdo);
        $this->incidents = new IncidentManager($pdo);
    }

    /** @return array Ingestion result including a durable SIEM log ID and correlation decision. */
    public function ingest(array $payload, string $actor = 'api_sensor'): array
    {
        $ownsTransaction = !$this->pdo->inTransaction();
        if ($ownsTransaction) {
            $this->pdo->beginTransaction();
        }

        try {
            $result = $this->ingestion->ingest($payload, $actor);
            if (!$result['success'] || !empty($result['duplicate'])) {
                if ($ownsTransaction) {
                    $this->pdo->commit();
                }
                return $result;
            }

            $alert = $result['alert'];
            // Legacy SIEM has WARNING, not MEDIUM. Keep canonical SOAR severity intact.
            $siemSeverity = $alert['severity'] === 'MEDIUM' ? 'WARNING' : $alert['severity'];
            $stmt = $this->pdo->prepare(
                'INSERT INTO logs (source_ip, severity, category, message, timestamp) VALUES (?, ?, ?, ?, ?)'
            );
            $stmt->execute([
                $alert['source_ip'],
                $siemSeverity,
                $alert['category'],
                $alert['message'],
                $alert['event_timestamp'],
            ]);
            $logId = (int) $this->pdo->lastInsertId();

            $correlation = $this->incidents->processAlert($alert, $logId, $actor);
            $result['log_id'] = $logId;
            $result['correlation'] = [
                'decision' => $correlation['decision'],
                'incident_id' => isset($correlation['incident']['id'])
                    ? (int) $correlation['incident']['id']
                    : null,
                'incident_number' => $correlation['incident']['incident_number'] ?? null,
            ];

            if ($ownsTransaction) {
                $this->pdo->commit();
            }
            return $result;
        } catch (Throwable $e) {
            if ($ownsTransaction && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }
}
