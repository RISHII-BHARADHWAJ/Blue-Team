<?php
/**
 * ThreatPulse SOAR - IOC Extractor
 * 
 * Deterministically extracts candidate Indicators of Compromise (IOCs)
 * from alert attributes, message text, and metadata.
 * 
 * Security Exclusions:
 * - RFC 1918 Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 * - Loopback (127.0.0.0/8, ::1, localhost)
 * - Link-local / Cloud Metadata (169.254.0.0/16, fe80::/10)
 * - Test / Example domains (example.com, test.local)
 */

require_once __DIR__ . '/IocNormalizer.php';
require_once __DIR__ . '/IocValidator.php';
require_once __DIR__ . '/AlertSchema.php';

class IocExtractor {

    private const DISALLOWED_DOMAINS = [
        'localhost',
        'example.com',
        'example.org',
        'example.net',
        'test.com',
        'test.local',
        'invalid',
    ];

    /**
     * Extract IOCs from a canonical alert object or array.
     * 
     * @param AlertSchema|array $alert Canonical alert
     * @param bool $allowPrivateIps Whether to include private IPs (default: false)
     * @return array List of ['type' => string, 'value' => string, 'source' => string]
     */
    public function extractFromAlert(AlertSchema|array $alert, bool $allowPrivateIps = false): array {
        $data = is_array($alert) ? $alert : $alert->toArray();
        $extracted = [];

        // 1. Direct Source IP
        if (!empty($data['source_ip'])) {
            $this->addCandidate($extracted, $data['source_ip'], 'source_ip', $allowPrivateIps);
        }

        // 2. Direct Destination IP
        if (!empty($data['destination_ip'])) {
            $this->addCandidate($extracted, $data['destination_ip'], 'destination_ip', $allowPrivateIps);
        }

        // 3. Direct IOC Field
        if (!empty($data['ioc_value'])) {
            $this->addCandidate($extracted, $data['ioc_value'], 'ioc_value', $allowPrivateIps, $data['ioc_type'] ?? null);
        }

        // 4. Message Text Extraction
        if (!empty($data['message'])) {
            $this->extractFromText($extracted, $data['message'], 'message', $allowPrivateIps);
        }

        // 5. Metadata Map
        if (!empty($data['metadata']) && is_array($data['metadata'])) {
            foreach ($data['metadata'] as $metaKey => $metaVal) {
                if (is_string($metaVal)) {
                    $this->addCandidate($extracted, $metaVal, "metadata.$metaKey", $allowPrivateIps);
                }
            }
        }

        // Deduplicate extracted items by type + value
        $dedup = [];
        foreach ($extracted as $item) {
            $key = $item['type'] . ':' . $item['value'];
            if (!isset($dedup[$key])) {
                $dedup[$key] = $item;
            }
        }

        return array_values($dedup);
    }

    /**
     * Extract IOC patterns from arbitrary unstructured text.
     */
    public function extractFromText(array &$extracted, string $text, string $sourceField, bool $allowPrivateIps): void {
        // Regex patterns for URLs, IPs, Hashes
        // A. URLs
        if (preg_match_all('/https?:\/\/[^\s\'"<>()]+/', $text, $matches)) {
            foreach ($matches[0] as $url) {
                $this->addCandidate($extracted, $url, $sourceField, $allowPrivateIps, IocNormalizer::TYPE_URL);
            }
        }

        // B. IPv4 Addresses
        if (preg_match_all('/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/', $text, $matches)) {
            foreach ($matches[0] as $ip) {
                $this->addCandidate($extracted, $ip, $sourceField, $allowPrivateIps, IocNormalizer::TYPE_IPV4);
            }
        }

        // C. SHA-256 Hashes
        if (preg_match_all('/\b[a-fA-F0-9]{64}\b/', $text, $matches)) {
            foreach ($matches[0] as $sha) {
                $this->addCandidate($extracted, $sha, $sourceField, $allowPrivateIps, IocNormalizer::TYPE_SHA256);
            }
        }

        // D. MD5 Hashes
        if (preg_match_all('/\b[a-fA-F0-9]{32}\b/', $text, $matches)) {
            foreach ($matches[0] as $md5) {
                $this->addCandidate($extracted, $md5, $sourceField, $allowPrivateIps, IocNormalizer::TYPE_MD5);
            }
        }
    }

    /**
     * Helper to validate, filter exclusions, normalize, and push candidate IOC.
     */
    private function addCandidate(
        array &$extracted,
        string $rawVal,
        string $sourceField,
        bool $allowPrivateIps,
        ?string $forcedType = null
    ): void {
        $trimmed = trim($rawVal);
        if ($trimmed === '') return;

        $type = $forcedType ? strtoupper(trim($forcedType)) : IocNormalizer::detectType($trimmed);
        if (!$type) return;

        // Apply Normalization
        $norm = IocNormalizer::normalize($type, $trimmed);
        if (!$norm['valid']) return;

        $val = $norm['value'];

        // Exclusions: IP Address Filters
        if ($norm['type'] === IocNormalizer::TYPE_IPV4) {
            // Check loopback, private, link-local, cloud metadata
            if ($val === '127.0.0.1' || str_starts_with($val, '127.')) return;
            if ($val === '169.254.169.254' || str_starts_with($val, '169.254.')) return;
            if ($val === '0.0.0.0' || $val === '255.255.255.255') return;

            if (!$allowPrivateIps && !filter_var($val, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
                return; // Exclude private RFC 1918 IPs from external threat intelligence
            }
        }

        if ($norm['type'] === IocNormalizer::TYPE_IPV6) {
            if ($val === '::1' || str_starts_with($val, 'fe80:') || str_starts_with($val, 'fc00:')) return;
        }

        // Exclusions: Disallowed / Example Domains
        if ($norm['type'] === IocNormalizer::TYPE_DOMAIN) {
            if (in_array(strtolower($val), self::DISALLOWED_DOMAINS, true)) return;
        }

        if ($norm['type'] === IocNormalizer::TYPE_URL) {
            $host = parse_url($val, PHP_URL_HOST);
            if ($host && in_array(strtolower($host), self::DISALLOWED_DOMAINS, true)) return;
            if ($host === '169.254.169.254' || $host === '127.0.0.1' || $host === 'localhost') return;
        }

        $extracted[] = [
            'type'   => $norm['type'],
            'value'  => $val,
            'source' => $sourceField,
        ];
    }
}
