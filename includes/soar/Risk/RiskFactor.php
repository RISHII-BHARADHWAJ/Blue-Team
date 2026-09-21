<?php
/**
 * ThreatPulse SOAR - Risk Factor Value Object
 * 
 * Represents an individual, fully explainable scoring factor contribution.
 */

class RiskFactor {
    public string $name;
    public string $value;
    public int $contribution;
    public int $max_possible;
    public string $reason;

    public function __construct(
        string $name,
        string $value,
        int $contribution,
        int $max_possible,
        string $reason
    ) {
        $this->name = $name;
        $this->value = $value;
        $this->contribution = $contribution;
        $this->max_possible = $max_possible;
        $this->reason = $reason;
    }

    public function toArray(): array {
        return [
            'name'         => $this->name,
            'value'        => $this->value,
            'contribution' => $this->contribution,
            'max_possible' => $this->max_possible,
            'reason'       => $this->reason,
        ];
    }
}
