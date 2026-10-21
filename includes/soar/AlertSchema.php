<?php
/**
 * ThreatPulse SOAR - Canonical Alert Schema
 * 
 * Defines the internal canonical data structure for all security alerts
 * ingested into the SOAR subsystem.
 * 
 * All fields are strongly typed with explicit nullability to cleanly support
 * both minimal legacy SIEM log records and rich external sensor telemetry.
 */

class AlertSchema {
    public bool $is_simulated;
    public string $source;
    public string $source_type;
    public ?string $source_event_id;
    public ?string $source_ip;
    public ?string $destination_ip;
    public ?int $source_port;
    public ?int $destination_port;
    public ?string $protocol;
    public string $severity;
    public string $category;
    public ?string $signature;
    public string $message;
    public string $event_timestamp;
    public string $received_at;
    public ?string $mitre_tactic;
    public ?string $mitre_technique;
    public ?string $ioc_type;
    public ?string $ioc_value;
    public array $metadata;

    /**
     * Supported canonical severity levels (SOAR Standard).
     */
    public const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

    /**
     * Supported canonical attack categories.
     */
    public const CATEGORIES = ['SSH', 'SQLi', 'XSS', 'RCE', 'SSTI', 'LFI', 'Other'];

    /**
     * Supported IOC types.
     */
    public const IOC_TYPES = ['IPV4', 'IPV6', 'DOMAIN', 'URL', 'MD5', 'SHA256', 'EMAIL'];

    public function __construct(
        string $message,
        string $severity = 'INFO',
        string $category = 'Other',
        ?string $source_ip = null,
        ?string $destination_ip = null,
        ?int $source_port = null,
        ?int $destination_port = null,
        ?string $protocol = null,
        ?string $signature = null,
        ?string $event_timestamp = null,
        string $source = 'threatpulse_siem',
        string $source_type = 'log',
        ?string $source_event_id = null,
        ?string $mitre_tactic = null,
        ?string $mitre_technique = null,
        ?string $ioc_type = null,
        ?string $ioc_value = null,
        array $metadata = [],
        ?string $received_at = null,
        bool $is_simulated = false
    ) {
        $this->is_simulated = $is_simulated;
        $this->message = $message;
        $this->severity = $severity;
        $this->category = $category;
        $this->source_ip = $source_ip;
        $this->destination_ip = $destination_ip;
        $this->source_port = $source_port;
        $this->destination_port = $destination_port;
        $this->protocol = $protocol ? strtoupper(trim($protocol)) : null;
        $this->signature = $signature;
        $this->event_timestamp = $event_timestamp ?: date('Y-m-d H:i:s');
        $this->source = $source;
        $this->source_type = $source_type;
        $this->source_event_id = $source_event_id;
        $this->mitre_tactic = $mitre_tactic;
        $this->mitre_technique = $mitre_technique;
        $this->ioc_type = $ioc_type ? strtoupper(trim($ioc_type)) : null;
        $this->ioc_value = $ioc_value;
        $this->metadata = $metadata;
        $this->received_at = $received_at ?: date('Y-m-d H:i:s');
    }

    /**
     * Convert canonical alert instance to associative array.
     */
    public function toArray(): array {
        return [
            'is_simulated'      => $this->is_simulated,
            'source'            => $this->source,
            'source_type'       => $this->source_type,
            'source_event_id'   => $this->source_event_id,
            'source_ip'         => $this->source_ip,
            'destination_ip'    => $this->destination_ip,
            'source_port'       => $this->source_port,
            'destination_port'  => $this->destination_port,
            'protocol'          => $this->protocol,
            'severity'          => $this->severity,
            'category'          => $this->category,
            'signature'         => $this->signature,
            'message'           => $this->message,
            'event_timestamp'   => $this->event_timestamp,
            'received_at'       => $this->received_at,
            'mitre_tactic'      => $this->mitre_tactic,
            'mitre_technique'   => $this->mitre_technique,
            'ioc_type'          => $this->ioc_type,
            'ioc_value'         => $this->ioc_value,
            'metadata'          => $this->metadata,
        ];
    }

    /**
     * Construct a canonical alert from an associative array.
     */
    public static function fromArray(array $data): self {
        return new self(
            message:          $data['message'] ?? '',
            severity:         $data['severity'] ?? 'INFO',
            category:         $data['category'] ?? 'Other',
            source_ip:        $data['source_ip'] ?? null,
            destination_ip:   $data['destination_ip'] ?? null,
            source_port:      isset($data['source_port']) ? (int)$data['source_port'] : null,
            destination_port: isset($data['destination_port']) ? (int)$data['destination_port'] : null,
            protocol:         $data['protocol'] ?? null,
            signature:        $data['signature'] ?? null,
            event_timestamp:  $data['event_timestamp'] ?? null,
            source:           $data['source'] ?? 'threatpulse_siem',
            source_type:      $data['source_type'] ?? 'log',
            source_event_id:  isset($data['source_event_id']) ? (string)$data['source_event_id'] : null,
            mitre_tactic:     $data['mitre_tactic'] ?? null,
            mitre_technique:  $data['mitre_technique'] ?? null,
            ioc_type:         $data['ioc_type'] ?? null,
            ioc_value:        $data['ioc_value'] ?? null,
            metadata:         is_array($data['metadata'] ?? null) ? $data['metadata'] : [],
            received_at:      $data['received_at'] ?? null,
            is_simulated:     ($data['is_simulated'] ?? false) === true
        );
    }
}
