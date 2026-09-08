<?php
/**
 * ThreatPulse SOAR - Action Definition Value Object
 *
 * Represents the static, immutable metadata contract for a registered
 * allowlisted playbook action. Handler class names are hard-coded here
 * in trusted application code — never read from database input.
 */
class ActionDefinition {
    public string $actionType;
    public string $description;
    public string $riskLevel;      // LOW | MEDIUM | HIGH
    public bool   $requiresApproval;
    public array  $allowedParameters;
    public int    $defaultTimeoutSeconds;
    public int    $maxRetries;
    public string $handlerClass;   // Hard-coded — never user-supplied

    public function __construct(
        string $actionType,
        string $description,
        string $riskLevel,
        bool   $requiresApproval,
        array  $allowedParameters,
        int    $defaultTimeoutSeconds,
        int    $maxRetries,
        string $handlerClass
    ) {
        $this->actionType              = $actionType;
        $this->description             = $description;
        $this->riskLevel               = $riskLevel;
        $this->requiresApproval        = $requiresApproval;
        $this->allowedParameters       = $allowedParameters;
        $this->defaultTimeoutSeconds   = $defaultTimeoutSeconds;
        $this->maxRetries              = $maxRetries;
        $this->handlerClass            = $handlerClass;
    }

    public function toArray(): array {
        return [
            'action_type'             => $this->actionType,
            'description'             => $this->description,
            'risk_level'              => $this->riskLevel,
            'requires_approval'       => $this->requiresApproval,
            'allowed_parameters'      => $this->allowedParameters,
            'default_timeout_seconds' => $this->defaultTimeoutSeconds,
            'max_retries'             => $this->maxRetries,
        ];
    }
}
