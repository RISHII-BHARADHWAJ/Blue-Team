<?php
/**
 * ThreatPulse SOAR - Threat Intelligence Provider Registry
 * 
 * Manages active provider instances and matches capable providers by IOC type.
 */

require_once __DIR__ . '/ThreatIntelProvider.php';
require_once __DIR__ . '/ThreatFoxProvider.php';
require_once __DIR__ . '/FeodoTrackerProvider.php';
require_once __DIR__ . '/AbuseIpdbProvider.php';
require_once __DIR__ . '/VirusTotalProvider.php';

class ThreatIntelProviderRegistry {
    /**
     * @var ThreatIntelProvider[]
     */
    private array $providers = [];

    public function __construct(bool $registerDefaults = true) {
        if ($registerDefaults) {
            $this->register(new ThreatFoxProvider());
            $this->register(new FeodoTrackerProvider());
            $this->register(new AbuseIpdbProvider());
            $this->register(new VirusTotalProvider());
        }
    }

    public function register(ThreatIntelProvider $provider): void {
        $this->providers[$provider->getName()] = $provider;
    }

    public function get(string $name): ?ThreatIntelProvider {
        return $this->providers[$name] ?? null;
    }

    /**
     * @return ThreatIntelProvider[]
     */
    public function getAll(): array {
        return array_values($this->providers);
    }

    /**
     * Retrieve only providers that support a given IOC type.
     * 
     * @param string $iocType
     * @return ThreatIntelProvider[]
     */
    public function getProvidersForType(string $iocType): array {
        $typeUpper = strtoupper(trim($iocType));
        $capable = [];

        foreach ($this->providers as $provider) {
            if (in_array($typeUpper, $provider->getSupportedTypes(), true)) {
                $capable[] = $provider;
            }
        }

        return $capable;
    }
}
