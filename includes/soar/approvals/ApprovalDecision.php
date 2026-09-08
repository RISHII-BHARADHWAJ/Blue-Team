<?php
/**
 * ThreatPulse SOAR - Approval Decision Value Object
 *
 * Immutable representation of an analyst's response to an approval request.
 */
class ApprovalDecision {
    public const DECISION_APPROVE = 'APPROVE';
    public const DECISION_REJECT  = 'REJECT';

    public readonly int     $approvalId;
    public readonly string  $decision;
    public readonly ?string $reason;
    public readonly int     $reviewerId;
    public readonly string  $reviewerTier;
    public readonly string  $timestamp;

    public function __construct(
        int     $approvalId,
        string  $decision,
        ?string $reason,
        int     $reviewerId,
        string  $reviewerTier
    ) {
        $normalizedDecision = strtoupper(trim($decision));
        if (!in_array($normalizedDecision, [self::DECISION_APPROVE, self::DECISION_REJECT], true)) {
            throw new InvalidArgumentException("Invalid approval decision: {$decision}. Must be APPROVE or REJECT.");
        }

        $this->approvalId   = $approvalId;
        $this->decision     = $normalizedDecision;
        $this->reason       = $reason !== null ? trim($reason) : null;
        $this->reviewerId   = $reviewerId;
        $this->reviewerTier = strtoupper(trim($reviewerTier));
        $this->timestamp    = date('Y-m-d H:i:s');
    }

    public function isApproved(): bool {
        return $this->decision === self::DECISION_APPROVE;
    }

    public function isRejected(): bool {
        return $this->decision === self::DECISION_REJECT;
    }
}
