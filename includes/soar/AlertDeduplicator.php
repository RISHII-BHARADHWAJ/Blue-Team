<?php
/**
 * ThreatPulse SOAR - Alert Deduplicator
 * 
 * Computes deterministic SHA-256 fingerprints across canonical alert fields
 * within a sliding time window (default: 5 minutes / 300 seconds).
 * 
 * Guarantees that duplicate burst alerts are recognized and deduplicated
 * without modifying or altering existing SIEM tables.
 */

require_once __DIR__ . '/AlertSchema.php';

class AlertDeduplicator {

    /**
     * Default deduplication time window in seconds (5 minutes).
     */
    public const DEFAULT_BUCKET_SECONDS = 300;

    /**
     * In-memory cache for runtime/test-execution deduplication tracking.
     */
    private static array $memoryCache = [];

    /**
     * Generate a deterministic SHA-256 fingerprint from a canonical alert.
     * 
     * Serialization format:
     * source:<source>\n
     * source_ip:<source_ip>\n
     * destination_ip:<dest_ip>\n
     * category:<category>\n
     * severity:<severity>\n
     * signature:<signature>\n
     * message:<normalized_message>\n
     * time_bucket:<bucket_number>
     * 
     * @param AlertSchema|array $alert Canonical alert
     * @param int $bucketSeconds Window size in seconds (default 300)
     * @return string SHA-256 hex string (64 characters)
     */
    public function generateFingerprint(AlertSchema|array $alert, int $bucketSeconds = self::DEFAULT_BUCKET_SECONDS): string {
        $data = is_array($alert) ? $alert : $alert->toArray();

        // 1. Calculate deterministic time bucket based on event timestamp
        $timestamp = isset($data['event_timestamp']) ? strtotime($data['event_timestamp']) : time();
        if ($timestamp === false || $timestamp <= 0) {
            $timestamp = time();
        }
        $timeBucket = (int)floor($timestamp / max(1, $bucketSeconds));

        // 2. Canonical serialization (ordered, lowercased keys, trimmed values)
        $lines = [
            'source:'         . strtolower(trim((string)($data['source'] ?? 'threatpulse_siem'))),
            'source_ip:'      . trim((string)($data['source_ip'] ?? '')),
            'destination_ip:' . trim((string)($data['destination_ip'] ?? '')),
            'category:'       . strtoupper(trim((string)($data['category'] ?? 'Other'))),
            'severity:'       . strtoupper(trim((string)($data['severity'] ?? 'INFO'))),
            'signature:'      . trim((string)($data['signature'] ?? '')),
            'message:'        . trim((string)($data['message'] ?? '')),
            'time_bucket:'    . $timeBucket,
        ];

        // Distinct source event IDs represent distinct observations, even within a burst.
        if (isset($data['source_event_id']) && $data['source_event_id'] !== '') $lines[] = 'source_event_id:' . $data['source_event_id'];
        if (!empty($data['is_simulated'])) $lines[] = 'is_simulated:true';
        $serialized = implode("\n", $lines);
        return hash('sha256', $serialized);
    }

    /**
     * Check if a fingerprint represents a duplicate alert and register it.
     * 
     * @param string $fingerprint SHA-256 fingerprint
     * @param ?PDO $pdo Database connection for persistent deduplication check
     * @param int $ttlSeconds Time-to-live for deduplication record
     * @return array ['is_duplicate' => bool, 'fingerprint' => string, 'reason' => string]
     */
    public function checkAndRegister(string $fingerprint, ?PDO $pdo = null, int $ttlSeconds = self::DEFAULT_BUCKET_SECONDS): array {
        $now = time();

        // 1. Check in-memory cache
        if (!$pdo && isset(self::$memoryCache[$fingerprint])) {
            $expiry = self::$memoryCache[$fingerprint];
            if ($expiry > $now) {
                return [
                    'is_duplicate' => true,
                    'fingerprint'  => $fingerprint,
                    'reason'       => "Identical alert fingerprint seen within {$ttlSeconds}s time window (Memory Cache)."
                ];
            }
        }

        // 2. Check Database (using existing rate_limits table with prefix 'soar_dedup_')
        if ($pdo) {
            try {
                $key = 'soar_dedup_' . substr($fingerprint, 0, 80);
                
                // Atomic registration serializes concurrent submissions of the same fingerprint.
                // Both operations participate in the caller's transaction, so retries after
                // an evidence/correlation failure are accepted instead of silently suppressed.
                // Keep one-off source event IDs from accumulating expired registrations.
                // Bound maintenance work and leave unrelated HTTP rate-limit keys intact.
                $cleanup = $pdo->prepare("DELETE FROM rate_limits
                    WHERE ip_action_key LIKE 'soar!_dedup!_%' ESCAPE '!'
                    AND window_start < DATE_SUB(NOW(), INTERVAL ? SECOND) LIMIT 1000");
                $cleanup->execute([$ttlSeconds]);
                $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE ip_action_key = ? AND window_start < DATE_SUB(NOW(), INTERVAL ? SECOND)");
                $stmt->execute([$key, $ttlSeconds]);
                $stmt = $pdo->prepare("INSERT INTO rate_limits (ip_action_key, request_count, window_start)
                    VALUES (?, 1, NOW()) ON DUPLICATE KEY UPDATE request_count = request_count + 1");
                $stmt->execute([$key]);
                if ($stmt->rowCount() !== 1) {
                    return ['is_duplicate' => true, 'fingerprint' => $fingerprint,
                        'reason' => "Identical alert fingerprint seen within {$ttlSeconds}s time window (Database)."];
                }

            } catch (Exception $e) {
                // A durable transaction must fail if deduplication cannot persist.
                throw $e;
            }
            return ['is_duplicate' => false, 'fingerprint' => $fingerprint, 'reason' => 'New distinct alert accepted.'];
        }

        // Register in memory
        self::$memoryCache[$fingerprint] = $now + $ttlSeconds;

        return [
            'is_duplicate' => false,
            'fingerprint'  => $fingerprint,
            'reason'       => 'New distinct alert accepted.'
        ];
    }

    /**
     * Clear in-memory deduplication cache (useful for testing).
     */
    public static function clearMemoryCache(): void {
        self::$memoryCache = [];
    }
}
