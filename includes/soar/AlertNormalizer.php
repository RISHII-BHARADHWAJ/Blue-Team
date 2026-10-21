<?php
/**
 * ThreatPulse SOAR - Alert Normalizer
 * 
 * Normalizes raw or legacy alert attributes into the canonical SOAR schema format:
 * - Severity mapping (WARNING -> MEDIUM, etc.)
 * - IP canonicalization (IPv4 / IPv6 normalization)
 * - Category normalization
 * - Strict timestamp parsing to 'Y-m-d H:i:s'
 * - Message preservation (never strip security context)
 */

require_once __DIR__ . '/AlertSchema.php';

class AlertNormalizer {

    /**
     * Severity mapping table: maps SIEM/legacy levels to canonical SOAR severity.
     */
    private const SEVERITY_MAP = [
        'CRITICAL' => 'CRITICAL',
        'HIGH'     => 'HIGH',
        'WARNING'  => 'MEDIUM',
        'WARN'     => 'MEDIUM',
        'MEDIUM'   => 'MEDIUM',
        'MED'      => 'MEDIUM',
        'INFO'     => 'INFO',
        'INFORMATIONAL' => 'INFO',
        'LOW'      => 'LOW',
        'DEBUG'    => 'LOW',
    ];

    /**
     * Category mapping table: matches case-insensitive patterns to canonical categories.
     */
    private const CATEGORY_MAP = [
        'ssh'   => 'SSH',
        'sqli'  => 'SQLi',
        'sql'   => 'SQLi',
        'xss'   => 'XSS',
        'rce'   => 'RCE',
        'ssti'  => 'SSTI',
        'lfi'   => 'LFI',
        'rfi'   => 'LFI',
        'other' => 'Other',
    ];

    /**
     * Normalize a raw alert array into a canonical AlertSchema object.
     * 
     * @throws InvalidArgumentException if critical fields (such as timestamp) are completely invalid.
     */
    public function normalize(array $raw): AlertSchema {
        $message = $this->normalizeMessage($raw['message'] ?? '');
        $severity = $this->normalizeSeverity($raw['severity'] ?? 'INFO');
        $category = $this->normalizeCategory($raw['category'] ?? 'Other');
        $sourceIp = $this->normalizeIp($raw['source_ip'] ?? null);
        $destIp = $this->normalizeIp($raw['destination_ip'] ?? null);
        $sourcePort = $this->normalizePort($raw['source_port'] ?? null);
        $destPort = $this->normalizePort($raw['destination_port'] ?? null);
        $protocol = !empty($raw['protocol']) ? strtoupper(trim((string)$raw['protocol'])) : null;
        $signature = !empty($raw['signature']) ? trim((string)$raw['signature']) : null;
        $eventTimestamp = $this->normalizeTimestamp($raw['event_timestamp'] ?? $raw['timestamp'] ?? null);
        $source = !empty($raw['source']) ? trim((string)$raw['source']) : 'threatpulse_siem';
        $sourceType = !empty($raw['source_type']) ? trim((string)$raw['source_type']) : 'log';
        $sourceEventId = isset($raw['source_event_id']) ? (string)$raw['source_event_id'] : (isset($raw['id']) ? (string)$raw['id'] : null);
        $mitreTactic = !empty($raw['mitre_tactic']) ? trim((string)$raw['mitre_tactic']) : null;
        $mitreTechnique = !empty($raw['mitre_technique']) ? trim((string)$raw['mitre_technique']) : null;
        $iocType = $this->normalizeIocType($raw['ioc_type'] ?? null);
        $iocValue = !empty($raw['ioc_value']) ? trim((string)$raw['ioc_value']) : null;
        $metadata = is_array($raw['metadata'] ?? null) ? $raw['metadata'] : [];
        $receivedAt = gmdate('Y-m-d H:i:s');

        return new AlertSchema(
            message:          $message,
            severity:         $severity,
            category:         $category,
            source_ip:        $sourceIp,
            destination_ip:   $destIp,
            source_port:      $sourcePort,
            destination_port: $destPort,
            protocol:         $protocol,
            signature:        $signature,
            event_timestamp:  $eventTimestamp,
            source:           $source,
            source_type:      $sourceType,
            source_event_id:  $sourceEventId,
            mitre_tactic:     $mitreTactic,
            mitre_technique:  $mitreTechnique,
            ioc_type:         $iocType,
            ioc_value:        $iocValue,
            metadata:         $metadata,
            received_at:      $receivedAt,
            is_simulated:     ($raw['is_simulated'] ?? false) === true
        );
    }

    /**
     * Normalize severity to canonical SOAR severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.
     * WARNING is strictly mapped to MEDIUM.
     */
    public function normalizeSeverity(?string $rawSeverity): string {
        if ($rawSeverity === null || trim($rawSeverity) === '') {
            return 'INFO';
        }
        $upper = strtoupper(trim($rawSeverity));
        return self::SEVERITY_MAP[$upper] ?? 'INFO';
    }

    /**
     * Normalize and canonicalize an IP address (IPv4 or IPv6).
     * Returns standard canonical format or null if empty/invalid.
     */
    public function normalizeIp(?string $rawIp): ?string {
        if ($rawIp === null) {
            return null;
        }
        $trimmed = trim($rawIp);
        if ($trimmed === '' || strtolower($trimmed) === 'unknown' || strtolower($trimmed) === 'none') {
            return null;
        }

        if (filter_var($trimmed, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $packed = @inet_pton($trimmed);
            return $packed !== false ? inet_ntop($packed) : $trimmed;
        }

        if (filter_var($trimmed, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $packed = @inet_pton($trimmed);
            return $packed !== false ? inet_ntop($packed) : strtolower($trimmed);
        }

        return $trimmed; // Return uncanonicalized string for validator to flag if invalid
    }

    /**
     * Normalize category into canonical category allowlist.
     */
    public function normalizeCategory(?string $rawCategory): string {
        if ($rawCategory === null || trim($rawCategory) === '') {
            return 'Other';
        }
        $lower = strtolower(trim($rawCategory));
        return self::CATEGORY_MAP[$lower] ?? (in_array(trim($rawCategory), AlertSchema::CATEGORIES) ? trim($rawCategory) : 'Other');
    }

    /**
     * Normalize timestamp into standard 'Y-m-d H:i:s'.
     */
    public function normalizeTimestamp($rawTimestamp): string {
        if ($rawTimestamp === null || $rawTimestamp === '') {
            return gmdate('Y-m-d H:i:s');
        }

        if (is_numeric($rawTimestamp)) {
            $ts = (float)$rawTimestamp;
            // Modern Unix milliseconds have 13 digits; retain compatibility with seconds.
            if ($ts >= 100000000000) $ts /= 1000;
            if ($ts > 0 && $ts <= 253402300799) return gmdate('Y-m-d H:i:s', (int)$ts);
        } elseif (is_string($rawTimestamp)) {
            try {
                $parsed = new DateTimeImmutable($rawTimestamp, new DateTimeZone('UTC'));
                if ($parsed->getTimestamp() > 0) return $parsed->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
            } catch (Exception $e) {
                // The caller receives the same structured validation error below.
            }
        }

        throw new InvalidArgumentException("Invalid timestamp format: " . htmlspecialchars((string)$rawTimestamp));
    }

    /**
     * Normalize port number (must be integer between 1 and 65535).
     */
    public function normalizePort($rawPort): ?int {
        if ($rawPort === null || $rawPort === '') {
            return null;
        }
        $intVal = (int)$rawPort;
        return ($intVal >= 1 && $intVal <= 65535) ? $intVal : null;
    }

    /**
     * Normalize IOC type.
     */
    public function normalizeIocType(?string $rawType): ?string {
        if ($rawType === null || trim($rawType) === '') {
            return null;
        }
        $upper = strtoupper(trim($rawType));
        return in_array($upper, AlertSchema::IOC_TYPES) ? $upper : null;
    }

    /**
     * Normalize message string.
     * Preserves exact text without stripping attack payloads or security details.
     */
    public function normalizeMessage(?string $rawMessage): string {
        if ($rawMessage === null) {
            return '';
        }
        return (string)$rawMessage;
    }
}
