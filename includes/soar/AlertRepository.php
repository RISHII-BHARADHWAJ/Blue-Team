<?php
/**
 * ThreatPulse SOAR - Alert Repository
 * 
 * Provides safe, read-only data access interfaces for querying existing SIEM logs
 * and SOAR alert metadata without modifying legacy tables.
 */

class AlertRepository {
    private PDO $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    /**
     * Fetch a single legacy SIEM log record by its integer ID.
     */
    public function fetchLegacyLog(int $logId): ?array {
        $stmt = $this->pdo->prepare("
            SELECT id, source_ip, severity, category, message, timestamp 
            FROM logs 
            WHERE id = ?
        ");
        $stmt->execute([$logId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Fetch recent legacy logs within an optional time threshold.
     */
    public function fetchRecentLegacyLogs(int $limit = 50, ?string $since = null): array {
        $limit = max(1, min(500, $limit));

        if ($since !== null) {
            $stmt = $this->pdo->prepare("
                SELECT id, source_ip, severity, category, message, timestamp 
                FROM logs 
                WHERE timestamp >= ?
                ORDER BY timestamp DESC 
                LIMIT ?
            ");
            $stmt->bindValue(1, $since, PDO::PARAM_STR);
            $stmt->bindValue(2, $limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        }

        $stmt = $this->pdo->prepare("
            SELECT id, source_ip, severity, category, message, timestamp 
            FROM logs 
            ORDER BY timestamp DESC 
            LIMIT ?
        ");
        $stmt->bindValue(1, $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Count total legacy logs.
     */
    public function countLegacyLogs(): int {
        return (int)$this->pdo->query("SELECT COUNT(*) FROM logs")->fetchColumn();
    }
}
