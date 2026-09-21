<?php
/**
 * ThreatPulse SOAR - Risk Assessment Model
 * 
 * Represents a complete, point-by-point explainable risk assessment output.
 */

require_once __DIR__ . '/RiskFactor.php';
require_once __DIR__ . '/RiskPolicy.php';

class RiskAssessment {
    public int $score;
    public string $priority;
    public string $confidence;
    /**
     * @var RiskFactor[]
     */
    public array $factors;
    public string $policy_version;
    public string $calculated_at;
    public string $calculated_by;

    public function __construct(
        int $score,
        string $priority,
        string $confidence,
        array $factors,
        string $policy_version = RiskPolicy::VERSION,
        ?string $calculated_at = null,
        string $calculated_by = 'system'
    ) {
        $this->score = max(0, min(100, $score));
        $this->priority = $priority;
        $this->confidence = in_array(strtoupper($confidence), ['HIGH', 'MEDIUM', 'LOW'], true) ? strtoupper($confidence) : 'MEDIUM';
        $this->factors = $factors;
        $this->policy_version = $policy_version;
        $this->calculated_at = $calculated_at ?: date('Y-m-d H:i:s');
        $this->calculated_by = $calculated_by;
    }

    public function toArray(): array {
        return [
            'score'            => $this->score,
            'priority'         => $this->priority,
            'confidence'       => $this->confidence,
            'policy_version'   => $this->policy_version,
            'calculated_at'    => $this->calculated_at,
            'calculated_by'    => $this->calculated_by,
            'factor_breakdown' => array_map(fn($f) => $f instanceof RiskFactor ? $f->toArray() : $f, $this->factors),
        ];
    }
}
