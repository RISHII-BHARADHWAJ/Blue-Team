<?php
/**
 * Read-only source-IP lookup in externally reported threat intelligence.
 * A matching listing is context, not a local detection or proof of compromise.
 */
declare(strict_types=1);

final class ThreatIntelMatcher
{
    public function __construct(private PDO $pdo) {}

    /** @return array<int,array<string,mixed>> */
    public function matchSourceIp(?string $sourceIp): array
    {
        if (!$sourceIp || !filter_var($sourceIp, FILTER_VALIDATE_IP)) {
            return [];
        }
        return $this->matchSourceIps([$sourceIp])[$sourceIp] ?? [];
    }

    /**
     * Batch-match up to 100 distinct alert IPs; results keyed by source IP.
     * Handles older local installations without threat-intelligence migration 007.
     *
     * @param array<int,mixed> $sourceIps
     * @return array<string,array<int,array<string,mixed>>>
     */
    public function matchSourceIps(array $sourceIps): array
    {
        $ips = [];
        foreach ($sourceIps as $ip) {
            if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[$ip] = $ip;
            }
            if (count($ips) >= 100) {
                break;
            }
        }
        if (!$ips) {
            return [];
        }

        $table = $this->pdo->query("SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = 'threat_feed_indicators'");
        if ((int)$table->fetchColumn() !== 1) {
            return [];
        }

        $values = array_values($ips);
        $placeholders = implode(',', array_fill(0, count($values), '?'));
        $stmt = $this->pdo->prepare("SELECT provider, indicator_type, indicator_value,
                   threat_type, malware_family, source_last_seen, fetched_at
                FROM threat_feed_indicators
                WHERE indicator_type IN ('IPV4', 'IPV6') AND indicator_value IN ($placeholders)
                ORDER BY provider ASC LIMIT 500");
        $stmt->execute($values);
        $matches = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $matches[$row['indicator_value']][] = $row;
        }
        return $matches;
    }
}
