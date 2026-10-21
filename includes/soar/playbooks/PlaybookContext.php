<?php
/**
 * ThreatPulse SOAR - Playbook Context
 *
 * Immutable execution context loaded exclusively from authoritative database state.
 * Client-supplied fields (risk_score, priority, severity, etc.) are NEVER trusted.
 * The context snapshot is created once at run-start and read-only thereafter.
 */
class PlaybookContext {
    public readonly array  $incident;
    public readonly array  $alerts;
    public readonly array  $iocs;
    public readonly array  $riskAssessment;
    public readonly array  $analyst;
    public readonly array  $playbookRun;
    public readonly string $mode;        // MANUAL | AUTOMATIC | DRY_RUN
    public readonly string $createdAt;

    public function __construct(
        array  $incident,
        array  $alerts         = [],
        array  $iocs           = [],
        array  $riskAssessment = [],
        array  $analyst        = [],
        array  $playbookRun    = [],
        string $mode           = 'MANUAL'
    ) {
        $this->incident       = $incident;
        $this->alerts         = $alerts;
        $this->iocs           = $iocs;
        $this->riskAssessment = $riskAssessment;
        $this->analyst        = $analyst;
        $this->playbookRun    = $playbookRun;
        $this->mode           = !empty($incident['is_simulated']) ? 'DRY_RUN' : (in_array(strtoupper($mode), ['MANUAL','AUTOMATIC','DRY_RUN'], true)
                                 ? strtoupper($mode) : 'MANUAL');
        $this->createdAt      = date('Y-m-d H:i:s');
    }

    public function isDryRun(): bool {
        return $this->mode === 'DRY_RUN';
    }

    /** Flat snapshot for template resolver consumption. */
    public function toTemplateScope(): array {
        $firstIoc = $this->iocs[0] ?? [];
        return [
            'incident' => [
                'id'              => $this->incident['id'] ?? '',
                'incident_number' => $this->incident['incident_number'] ?? '',
                'title'           => $this->incident['title'] ?? '',
                'description'     => $this->incident['description'] ?? '',
                'severity'        => $this->incident['severity'] ?? '',
                'status'          => $this->incident['status'] ?? '',
                'priority'        => $this->incident['priority'] ?? '',
                'risk_score'      => $this->incident['risk_score'] ?? 0,
                'attack_category' => $this->incident['attack_category'] ?? '',
                'source_ip'       => $this->alerts[0]['source_ip'] ?? '',
            ],
            'ioc' => [
                'value'      => $firstIoc['ioc_value'] ?? '',
                'type'       => $firstIoc['ioc_type'] ?? '',
                'assessment' => $firstIoc['assessment'] ?? '',
            ],
            'analyst' => [
                'id'       => $this->analyst['id'] ?? '',
                'username' => $this->analyst['username'] ?? '',
            ],
            'run' => [
                'run_uuid' => $this->playbookRun['run_uuid'] ?? '',
                'mode'     => $this->mode,
            ],
        ];
    }

    public function toArray(): array {
        return [
            'incident'        => $this->incident,
            'alerts'          => $this->alerts,
            'iocs'            => $this->iocs,
            'risk_assessment' => $this->riskAssessment,
            'analyst'         => $this->analyst,
            'playbook_run'    => $this->playbookRun,
            'mode'            => $this->mode,
            'created_at'      => $this->createdAt,
        ];
    }
}
