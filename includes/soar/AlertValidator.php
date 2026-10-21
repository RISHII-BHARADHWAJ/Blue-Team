<?php
/**
 * ThreatPulse SOAR - Alert Validator
 * 
 * Validates incoming raw alert payloads prior to normalization and ingestion.
 * Returns structured validation error arrays without throwing raw exceptions
 * or leaking internal database structures.
 * 
 * Safety: Never executes user input or performs dynamic evaluation.
 */

require_once __DIR__ . '/AlertSchema.php';

class AlertValidator {

    /**
     * Maximum allowed string field lengths to prevent buffer exhaustion & DoS.
     */
    public const MAX_LENGTHS = [
        'message'          => 65535,
        'source_ip'        => 45,
        'destination_ip'   => 45,
        'source'           => 100,
        'source_type'      => 50,
        'source_event_id'  => 64,
        'signature'        => 255,
        'category'         => 50,
        'mitre_tactic'     => 255,
        'mitre_technique'  => 255,
        'ioc_value'        => 500,
    ];

    /**
     * Validate raw alert data.
     * 
     * @param array $data Raw input array
     * @return array ['valid' => bool, 'errors' => array]
     */
    public function validate(array $data): array {
        $errors = [];

        // Reject structured values before casts/normalization can hide malformed input.
        foreach (array_merge(array_keys(self::MAX_LENGTHS), ['severity', 'protocol', 'ioc_type']) as $field) {
            if (isset($data[$field]) && !is_string($data[$field])
                && !($field === 'source_event_id' && is_int($data[$field]))) {
                $errors[] = ['field' => $field, 'code' => 'INVALID_TYPE', 'message' => "$field must be a string."];
            }
        }
        if (array_key_exists('is_simulated', $data) && !is_bool($data['is_simulated'])) {
            $errors[] = ['field' => 'is_simulated', 'code' => 'INVALID_TYPE', 'message' => 'is_simulated must be a JSON boolean.'];
        }
        if ($errors) return ['valid' => false, 'errors' => $errors];

        // 1. Required: message
        if (!isset($data['message']) || trim((string)$data['message']) === '') {
            $errors[] = [
                'field'   => 'message',
                'code'    => 'REQUIRED_FIELD_MISSING',
                'message' => 'The message field is required and cannot be empty.'
            ];
        }

        // 2. Length Validations
        foreach (self::MAX_LENGTHS as $field => $maxLength) {
            if (isset($data[$field]) && is_string($data[$field])) {
                if (strlen($data[$field]) > $maxLength) {
                    $errors[] = [
                        'field'   => $field,
                        'code'    => 'FIELD_OVERSIZED',
                        'message' => "The $field field exceeds maximum allowed length of $maxLength bytes."
                    ];
                }
            }
        }

        // 3. IP Validations (if provided)
        if (!empty($data['source_ip'])) {
            $ip = trim((string)$data['source_ip']);
            if (strtolower($ip) !== 'unknown' && !filter_var($ip, FILTER_VALIDATE_IP)) {
                $errors[] = [
                    'field'   => 'source_ip',
                    'code'    => 'INVALID_IP',
                    'message' => 'The source_ip must be a valid IPv4 or IPv6 address.'
                ];
            }
        }

        if (!empty($data['destination_ip'])) {
            $ip = trim((string)$data['destination_ip']);
            if (strtolower($ip) !== 'unknown' && !filter_var($ip, FILTER_VALIDATE_IP)) {
                $errors[] = [
                    'field'   => 'destination_ip',
                    'code'    => 'INVALID_IP',
                    'message' => 'The destination_ip must be a valid IPv4 or IPv6 address.'
                ];
            }
        }

        // 4. Port Validations (if provided)
        if (isset($data['source_port']) && $data['source_port'] !== null && $data['source_port'] !== '') {
            if (!is_numeric($data['source_port']) || (int)$data['source_port'] < 1 || (int)$data['source_port'] > 65535) {
                $errors[] = [
                    'field'   => 'source_port',
                    'code'    => 'INVALID_PORT',
                    'message' => 'The source_port must be an integer between 1 and 65535.'
                ];
            }
        }

        if (isset($data['destination_port']) && $data['destination_port'] !== null && $data['destination_port'] !== '') {
            if (!is_numeric($data['destination_port']) || (int)$data['destination_port'] < 1 || (int)$data['destination_port'] > 65535) {
                $errors[] = [
                    'field'   => 'destination_port',
                    'code'    => 'INVALID_PORT',
                    'message' => 'The destination_port must be an integer between 1 and 65535.'
                ];
            }
        }

        // 5. Severity Validation (if explicitly provided)
        if (isset($data['severity']) && trim((string)$data['severity']) !== '') {
            $sevUpper = strtoupper(trim((string)$data['severity']));
            $allowedSeverities = ['CRITICAL', 'HIGH', 'WARNING', 'WARN', 'MEDIUM', 'MED', 'INFO', 'INFORMATIONAL', 'LOW', 'DEBUG'];
            if (!in_array($sevUpper, $allowedSeverities, true)) {
                $errors[] = [
                    'field'   => 'severity',
                    'code'    => 'INVALID_SEVERITY',
                    'message' => "Severity '$sevUpper' is unsupported. Allowed: CRITICAL, HIGH, MEDIUM, LOW, INFO."
                ];
            }
        }

        // 6. Timestamp Validation (if provided)
        $ts = $data['event_timestamp'] ?? $data['timestamp'] ?? null;
        if ($ts !== null && $ts !== '') {
            if (is_string($ts)) {
                $parsed = strtotime($ts);
                if ($parsed === false || $parsed <= 0) {
                    $errors[] = [
                        'field'   => 'event_timestamp',
                        'code'    => 'INVALID_TIMESTAMP',
                        'message' => 'The event_timestamp is not a recognized date or ISO-8601 string.'
                    ];
                }
            } elseif (!is_numeric($ts) || (int)$ts <= 0) {
                $errors[] = [
                    'field'   => 'event_timestamp',
                    'code'    => 'INVALID_TIMESTAMP',
                    'message' => 'The event_timestamp must be a valid numeric epoch timestamp or date string.'
                ];
            }
        }

        // 7. IOC Type Validation (if provided)
        if (isset($data['ioc_type']) && trim((string)$data['ioc_type']) !== '') {
            $typeUpper = strtoupper(trim((string)$data['ioc_type']));
            if (!in_array($typeUpper, AlertSchema::IOC_TYPES, true)) {
                $errors[] = [
                    'field'   => 'ioc_type',
                    'code'    => 'INVALID_IOC_TYPE',
                    'message' => "IOC type '$typeUpper' is invalid. Allowed: " . implode(', ', AlertSchema::IOC_TYPES)
                ];
            }
        }

        // 8. Minimum Identity Assertion: At least one identifying characteristic must exist
        $hasIdentifier = !empty($data['source_ip']) 
                      || !empty($data['ioc_value']) 
                      || !empty($data['signature']) 
                      || !empty($data['destination_ip'])
                      || !empty($data['source_event_id'])
                      || !empty($data['id']);

        if (!$hasIdentifier && empty($errors)) {
            $errors[] = [
                'field'   => 'source_ip',
                'code'    => 'MISSING_IDENTIFIER',
                'message' => 'Alert must contain at least one identifying indicator (source_ip, ioc_value, signature, destination_ip, or source_event_id).'
            ];
        }

        return [
            'valid'  => empty($errors),
            'errors' => $errors
        ];
    }
}
