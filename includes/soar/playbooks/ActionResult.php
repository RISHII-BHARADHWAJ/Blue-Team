<?php
/**
 * ThreatPulse SOAR - Action Result Value Object
 *
 * Standardized output returned by every action handler.
 * Never contains raw credentials, secrets, or authorization headers.
 */
class ActionResult {
    public const STATUS_SUCCESS          = 'SUCCESS';
    public const STATUS_FAILED           = 'FAILED';
    public const STATUS_SKIPPED          = 'SKIPPED';
    public const STATUS_WAITING_APPROVAL = 'WAITING_APPROVAL';

    public string  $status;
    public string  $message;
    public array   $data;
    public bool    $isDryRun;
    public array   $evidence;

    public function __construct(
        string $status,
        string $message,
        array  $data    = [],
        bool   $isDryRun = false,
        array  $evidence = []
    ) {
        $validStatuses = [
            self::STATUS_SUCCESS,
            self::STATUS_FAILED,
            self::STATUS_SKIPPED,
            self::STATUS_WAITING_APPROVAL,
        ];
        if (!in_array($status, $validStatuses, true)) {
            throw new InvalidArgumentException("Invalid ActionResult status: {$status}");
        }
        $this->status   = $status;
        $this->message  = $message;
        $this->data     = $data;
        $this->isDryRun = $isDryRun;
        $this->evidence = $evidence;
    }

    public function isSuccess(): bool { return $this->status === self::STATUS_SUCCESS; }
    public function isFailed():  bool { return $this->status === self::STATUS_FAILED; }

    public function toArray(): array {
        return [
            'status'   => $this->status,
            'message'  => $this->message,
            'data'     => $this->data,
            'dry_run'  => $this->isDryRun,
            'evidence' => $this->evidence,
        ];
    }
}
