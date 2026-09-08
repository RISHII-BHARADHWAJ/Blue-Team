<?php
/**
 * ThreatPulse SOAR - Threat Intelligence Provider Interface & Result Contract
 * 
 * Defines the standard contract for all external threat intelligence providers
 * (ThreatFox, Feodo Tracker, AbuseIPDB, VirusTotal) and normalized ProviderResult structure.
 */

class ProviderResult {
    public string $provider;
    public string $status; // 'SUCCESS' | 'FAILED' | 'RATE_LIMITED'
    public string $ioc_type;
    public string $ioc_value;
    public int $reputation; // 0 to 100 (how malicious)
    public int $confidence; // 0 to 100 (confidence level)
    public array $categories;
    public ?string $malware_family;
    public ?string $first_seen;
    public ?string $last_seen;
    public ?array $raw_response;
    public array $summary;
    public string $retrieved_at;
    public int $ttl;
    public bool $cached;

    public function __construct(
        string $provider,
        string $status,
        string $ioc_type,
        string $ioc_value,
        int $reputation = 0,
        int $confidence = 50,
        array $categories = [],
        ?string $malware_family = null,
        ?string $first_seen = null,
        ?string $last_seen = null,
        ?array $raw_response = null,
        array $summary = [],
        ?string $retrieved_at = null,
        int $ttl = 3600,
        bool $cached = false
    ) {
        $this->provider = $provider;
        $this->status = $status;
        $this->ioc_type = $ioc_type;
        $this->ioc_value = $ioc_value;
        $this->reputation = max(0, min(100, $reputation));
        $this->confidence = max(0, min(100, $confidence));
        $this->categories = $categories;
        $this->malware_family = $malware_family;
        $this->first_seen = $first_seen;
        $this->last_seen = $last_seen;
        $this->raw_response = $raw_response;
        $this->summary = $summary;
        $this->retrieved_at = $retrieved_at ?: date('Y-m-d H:i:s');
        $this->ttl = $ttl;
        $this->cached = $cached;
    }

    public function toArray(): array {
        return [
            'provider'       => $this->provider,
            'status'         => $this->status,
            'ioc_type'       => $this->ioc_type,
            'ioc_value'      => $this->ioc_value,
            'reputation'     => $this->reputation,
            'confidence'     => $this->confidence,
            'categories'     => $this->categories,
            'malware_family' => $this->malware_family,
            'first_seen'     => $this->first_seen,
            'last_seen'      => $this->last_seen,
            'raw_response'   => $this->raw_response,
            'summary'        => $this->summary,
            'retrieved_at'   => $this->retrieved_at,
            'ttl'            => $this->ttl,
            'cached'         => $this->cached,
        ];
    }
}

interface ThreatIntelProvider {
    public function getName(): string;
    public function getSupportedTypes(): array;
    public function lookup(string $iocType, string $iocValue): ProviderResult;
    public function getRateLimit(): array;
}
