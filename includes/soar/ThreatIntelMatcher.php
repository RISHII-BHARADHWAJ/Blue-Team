<?php
/**
 * Read-only source-IP lookup in externally reported threat intelligence.
 * A matching listing is context, not a local detection or proof of compromise.
 */
declare(strict_types=1);

final class ThreatIntelMatcher
{
    public function __construct(private PDO $pdo) {}

    public function matchSourceIp(?string $sourceIp): array
    {
        if (!$sourceIp || !filter_var($sourceIp, FILTER_VALIDATE_IP)) {
            return [];
        }
        // Migration 007 may not exist on older, manually initialized databases.
        $table = $this->pdo->query("SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = 'threat_feed_indicators'");
        if ((int)$table->fetchColumn() !== 1) {
            return [];
        }
        $type = filter_var($sourceIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'IPV4' : 'IPV6';
        $stmt = $this->pdo->prepare("SELECT provider, indicator_type, indicator_value,
                   threat_type, malware_family, source_last_seen, fetched_at
                FROM threat_feed_indicators
                WHERE indicator_type = ? AND indicator_value = ?
                ORDER BY provider ASC LIMIT 20");
        $stmt->execute([$type, $sourceIp]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
