<?php
/**
 * ThreatPulse SOAR - IOC Normalizer
 * 
 * Detects, validates, and normalizes Indicator of Compromise (IOC) values
 * across supported types: IPV4, IPV6, DOMAIN, URL, MD5, SHA256, EMAIL.
 */

class IocNormalizer {

    public const TYPE_IPV4   = 'IPV4';
    public const TYPE_IPV6   = 'IPV6';
    public const TYPE_DOMAIN = 'DOMAIN';
    public const TYPE_URL    = 'URL';
    public const TYPE_MD5    = 'MD5';
    public const TYPE_SHA256 = 'SHA256';
    public const TYPE_EMAIL  = 'EMAIL';

    public const SUPPORTED_TYPES = [
        self::TYPE_IPV4,
        self::TYPE_IPV6,
        self::TYPE_DOMAIN,
        self::TYPE_URL,
        self::TYPE_MD5,
        self::TYPE_SHA256,
        self::TYPE_EMAIL,
    ];

    /**
     * Detect IOC type from a raw string value.
     */
    public static function detectType(string $raw): ?string {
        $trimmed = trim($raw);
        if ($trimmed === '') return null;

        // 1. IP Addresses
        if (filter_var($trimmed, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::TYPE_IPV4;
        }
        if (filter_var($trimmed, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::TYPE_IPV6;
        }

        // 2. Hashes
        if (preg_match('/^[a-fA-F0-9]{32}$/', $trimmed)) {
            return self::TYPE_MD5;
        }
        if (preg_match('/^[a-fA-F0-9]{64}$/', $trimmed)) {
            return self::TYPE_SHA256;
        }

        // 3. Email
        if (filter_var($trimmed, FILTER_VALIDATE_EMAIL)) {
            return self::TYPE_EMAIL;
        }

        // 4. URL
        if (preg_match('/^https?:\/\//i', $trimmed) && filter_var($trimmed, FILTER_VALIDATE_URL)) {
            return self::TYPE_URL;
        }

        // 5. Domain (RFC 1035 / 1123 regex)
        if (preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/i', $trimmed)) {
            return self::TYPE_DOMAIN;
        }

        return null;
    }

    /**
     * Normalize an IOC value into its canonical form.
     * 
     * @param string $type Explicit or detected IOC type
     * @param string $value Raw IOC value
     * @return array ['type' => string, 'value' => string, 'valid' => bool]
     */
    public static function normalize(string $type, string $value): array {
        $typeUpper = strtoupper(trim($type));
        $val = trim($value);

        if (!in_array($typeUpper, self::SUPPORTED_TYPES, true)) {
            return ['type' => $typeUpper, 'value' => $val, 'valid' => false, 'error' => 'UNSUPPORTED_TYPE'];
        }

        switch ($typeUpper) {
            case self::TYPE_IPV4:
                if (!filter_var($val, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    return ['type' => self::TYPE_IPV4, 'value' => $val, 'valid' => false, 'error' => 'INVALID_IPV4'];
                }
                $packed = @inet_pton($val);
                return ['type' => self::TYPE_IPV4, 'value' => inet_ntop($packed), 'valid' => true];

            case self::TYPE_IPV6:
                if (!filter_var($val, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    return ['type' => self::TYPE_IPV6, 'value' => $val, 'valid' => false, 'error' => 'INVALID_IPV6'];
                }
                $packed = @inet_pton($val);
                return ['type' => self::TYPE_IPV6, 'value' => strtolower(inet_ntop($packed)), 'valid' => true];

            case self::TYPE_DOMAIN:
                $cleaned = strtolower(rtrim($val, '.'));
                if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i', $cleaned) || strlen($cleaned) > 253) {
                    return ['type' => self::TYPE_DOMAIN, 'value' => $cleaned, 'valid' => false, 'error' => 'INVALID_DOMAIN'];
                }
                return ['type' => self::TYPE_DOMAIN, 'value' => $cleaned, 'valid' => true];

            case self::TYPE_URL:
                if (!preg_match('/^https?:\/\//i', $val) || !filter_var($val, FILTER_VALIDATE_URL) || strlen($val) > 500) {
                    return ['type' => self::TYPE_URL, 'value' => $val, 'valid' => false, 'error' => 'INVALID_URL'];
                }
                $parts = parse_url($val);
                if (!$parts || empty($parts['host'])) {
                    return ['type' => self::TYPE_URL, 'value' => $val, 'valid' => false, 'error' => 'MALFORMED_URL'];
                }
                $scheme = strtolower($parts['scheme'] ?? 'http');
                $host = strtolower($parts['host']);
                $port = isset($parts['port']) ? ':' . $parts['port'] : '';
                $path = $parts['path'] ?? '/';
                $query = isset($parts['query']) ? '?' . $parts['query'] : '';
                $fragment = isset($parts['fragment']) ? '#' . $parts['fragment'] : '';
                
                $canonicalUrl = "{$scheme}://{$host}{$port}{$path}{$query}{$fragment}";
                return ['type' => self::TYPE_URL, 'value' => $canonicalUrl, 'valid' => true];

            case self::TYPE_MD5:
                $lower = strtolower($val);
                if (!preg_match('/^[a-f0-9]{32}$/', $lower)) {
                    return ['type' => self::TYPE_MD5, 'value' => $val, 'valid' => false, 'error' => 'INVALID_MD5'];
                }
                return ['type' => self::TYPE_MD5, 'value' => $lower, 'valid' => true];

            case self::TYPE_SHA256:
                $lower = strtolower($val);
                if (!preg_match('/^[a-f0-9]{64}$/', $lower)) {
                    return ['type' => self::TYPE_SHA256, 'value' => $val, 'valid' => false, 'error' => 'INVALID_SHA256'];
                }
                return ['type' => self::TYPE_SHA256, 'value' => $lower, 'valid' => true];

            case self::TYPE_EMAIL:
                if (!filter_var($val, FILTER_VALIDATE_EMAIL) || strlen($val) > 254) {
                    return ['type' => self::TYPE_EMAIL, 'value' => $val, 'valid' => false, 'error' => 'INVALID_EMAIL'];
                }
                $parts = explode('@', $val, 2);
                $canonicalEmail = $parts[0] . '@' . strtolower($parts[1]);
                return ['type' => self::TYPE_EMAIL, 'value' => $canonicalEmail, 'valid' => true];

            default:
                return ['type' => $typeUpper, 'value' => $val, 'valid' => false, 'error' => 'UNSUPPORTED_TYPE'];
        }
    }
}
