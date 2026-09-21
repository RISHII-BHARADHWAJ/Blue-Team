<?php
/**
 * ThreatPulse SOAR - Approval Validator
 *
 * Enforces business rules, state machine transitions, input hygiene,
 * reason validation, and anti-tampering guards for approval requests.
 */

require_once __DIR__ . '/ApprovalDecision.php';
require_once __DIR__ . '/../SoarAuth.php';

class ApprovalValidator {
    public const STATE_PENDING   = 'PENDING';
    public const STATE_APPROVED  = 'APPROVED';
    public const STATE_REJECTED  = 'REJECTED';
    public const STATE_EXPIRED   = 'EXPIRED';
    public const STATE_CANCELLED = 'CANCELLED';

    // State machine: current_state => [allowed next states]
    private const ALLOWED_TRANSITIONS = [
        self::STATE_PENDING   => [self::STATE_APPROVED, self::STATE_REJECTED, self::STATE_EXPIRED, self::STATE_CANCELLED],
        self::STATE_APPROVED  => [],
        self::STATE_REJECTED  => [],
        self::STATE_EXPIRED   => [],
        self::STATE_CANCELLED => [],
    ];

    // Forbidden client fields that must NEVER be accepted from HTTP request bodies
    public const FORBIDDEN_CLIENT_FIELDS = [
        'risk_score',
        'priority',
        'incident_id',
        'playbook_id',
        'action_type',
        'action_parameters',
        'approver_tier',
        'required_tier',
        'status',
        'created_at',
        'expires_at',
        'payload_hash',
    ];

    /**
     * Verify that a state transition is permitted by the state machine.
     */
    public function validateTransition(string $currentStatus, string $targetStatus): void {
        $curr = strtoupper(trim($currentStatus));
        $next = strtoupper(trim($targetStatus));

        if (!array_key_exists($curr, self::ALLOWED_TRANSITIONS)) {
            throw new InvalidArgumentException("Unknown current approval status: {$curr}");
        }

        $allowed = self::ALLOWED_TRANSITIONS[$curr];
        if (!in_array($next, $allowed, true)) {
            throw new RuntimeException("Invalid approval state transition: {$curr} -> {$next}. An approval cannot transition from {$curr}.");
        }
    }

    /**
     * Validate incoming HTTP input payload against client-supplied tampering.
     */
    public function assertNoClientTampering(array $input): void {
        foreach (self::FORBIDDEN_CLIENT_FIELDS as $field) {
            if (array_key_exists($field, $input)) {
                throw new InvalidArgumentException("Tampering detected: client may not supply '{$field}'.");
            }
        }
    }

    /**
     * Validate rejection reason.
     * Minimum 10 characters, maximum 1000 characters.
     * Sanitizes untrusted text and strips HTML tags.
     */
    public function validateAndNormalizeReason(string $reason): string {
        // Strip any HTML or PHP tags to prevent stored XSS
        $sanitized = trim(strip_tags($reason));
        $length = mb_strlen($sanitized);

        if ($length < 10) {
            throw new InvalidArgumentException("Rejection reason must be at least 10 characters long (received {$length}).");
        }
        if ($length > 1000) {
            throw new InvalidArgumentException("Rejection reason exceeds maximum limit of 1000 characters (received {$length}).");
        }

        // Check for empty/whitespace-only evasion
        if (preg_match('/^[\s\.\-_]+$/', $sanitized)) {
            throw new InvalidArgumentException("Rejection reason must contain meaningful explanatory text.");
        }

        return $sanitized;
    }

    /**
     * Validate reviewer tier meets the required tier for the approval.
     */
    public function assertApproverAuthorized(string $reviewerTier, string $requiredTier): void {
        if (!SoarAuth::meetsMinimumTier($reviewerTier, $requiredTier)) {
            throw new RuntimeException("Authorization denied: Approver tier '{$reviewerTier}' does not meet required tier '{$requiredTier}'.");
        }

        // Must also have general approve_actions capability
        if (!SoarAuth::hasPermission($reviewerTier, 'approve_actions')) {
            throw new RuntimeException("Authorization denied: Tier '{$reviewerTier}' lacks 'approve_actions' permission.");
        }
    }

    /**
     * Validate approval expiration against authoritative server time.
     */
    public function assertNotExpired(string $expiresAt): void {
        $expiryTimestamp = strtotime($expiresAt);
        if ($expiryTimestamp === false || $expiryTimestamp <= time()) {
            throw new RuntimeException("Approval request has expired (expiry: {$expiresAt}, current time: " . date('Y-m-d H:i:s') . ").");
        }
    }

    /**
     * Verify payload hash integrity (recalculate and compare).
     */
    public function assertPayloadIntegrity(string $storedHash, string $currentPayloadJson): void {
        $computedHash = hash('sha256', $currentPayloadJson);
        if (!hash_equals($storedHash, $computedHash)) {
            throw new RuntimeException("Approval integrity violation: Action payload hash does not match stored hash. Execution rejected.");
        }
    }
}
