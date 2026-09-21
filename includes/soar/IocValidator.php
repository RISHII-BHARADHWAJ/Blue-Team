<?php
/**
 * ThreatPulse SOAR - IOC Validator
 * 
 * Enforces strict syntactic validation, length limits, character restrictions,
 * and URL scheme security on Indicator of Compromise (IOC) values.
 * 
 * Safety: Performs ZERO outbound network requests or DNS resolution.
 */

require_once __DIR__ . '/IocNormalizer.php';

class IocValidator {

    public const MAX_IOC_LENGTH = 500;

    /**
     * Validate an IOC type and value.
     * 
     * @param string $type IOC Type
     * @param string $value IOC Value
     * @return array ['valid' => bool, 'errors' => array]
     */
    public static function validate(string $type, string $value): array {
        $errors = [];
        $typeUpper = strtoupper(trim($type));

        // 1. Length & Null-byte check
        if (strlen($value) === 0) {
            $errors[] = ['code' => 'EMPTY_VALUE', 'message' => 'IOC value cannot be empty.'];
            return ['valid' => false, 'errors' => $errors];
        }

        if (strlen($value) > self::MAX_IOC_LENGTH) {
            $errors[] = ['code' => 'VALUE_OVERSIZED', 'message' => 'IOC value exceeds maximum allowed length of 500 bytes.'];
        }

        if (str_contains($value, "\0") || preg_match('/[\x00-\x1F\x7F]/', $value)) {
            $errors[] = ['code' => 'CONTROL_CHARACTERS_DETECTED', 'message' => 'IOC value contains illegal control characters or null bytes.'];
        }

        // 2. Type Support check
        if (!in_array($typeUpper, IocNormalizer::SUPPORTED_TYPES, true)) {
            $errors[] = ['code' => 'UNSUPPORTED_IOC_TYPE', 'message' => "Unsupported IOC type '{$typeUpper}'."];
            return ['valid' => false, 'errors' => $errors];
        }

        // 3. Type-Specific Syntactic Checks
        switch ($typeUpper) {
            case IocNormalizer::TYPE_IPV4:
                if (!filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $errors[] = ['code' => 'INVALID_IPV4', 'message' => 'Invalid IPv4 address format.'];
                }
                break;

            case IocNormalizer::TYPE_IPV6:
                if (!filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $errors[] = ['code' => 'INVALID_IPV6', 'message' => 'Invalid IPv6 address format.'];
                }
                break;

            case IocNormalizer::TYPE_DOMAIN:
                if (!preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/', $value) || strlen($value) > 253) {
                    $errors[] = ['code' => 'INVALID_DOMAIN', 'message' => 'Invalid domain name syntax.'];
                }
                break;

            case IocNormalizer::TYPE_URL:
                $parts = parse_url($value);
                if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
                    $errors[] = ['code' => 'MALFORMED_URL', 'message' => 'Malformed URL structure.'];
                } else {
                    $scheme = strtolower($parts['scheme']);
                    if (!in_array($scheme, ['http', 'https'], true)) {
                        $errors[] = ['code' => 'UNSUPPORTED_URL_SCHEME', 'message' => "URL scheme '{$scheme}' is forbidden. Only HTTP/HTTPS allowed."];
                    }
                }
                break;

            case IocNormalizer::TYPE_MD5:
                if (!preg_match('/^[a-fA-F0-9]{32}$/', $value)) {
                    $errors[] = ['code' => 'INVALID_MD5', 'message' => 'MD5 hash must be exactly 32 hexadecimal characters.'];
                }
                break;

            case IocNormalizer::TYPE_SHA256:
                if (!preg_match('/^[a-fA-F0-9]{64}$/', $value)) {
                    $errors[] = ['code' => 'INVALID_SHA256', 'message' => 'SHA-256 hash must be exactly 64 hexadecimal characters.'];
                }
                break;

            case IocNormalizer::TYPE_EMAIL:
                if (!filter_var($value, FILTER_VALIDATE_EMAIL) || strlen($value) > 254) {
                    $errors[] = ['code' => 'INVALID_EMAIL', 'message' => 'Invalid email address syntax.'];
                }
                break;
        }

        return [
            'valid'  => empty($errors),
            'errors' => $errors
        ];
    }
}
