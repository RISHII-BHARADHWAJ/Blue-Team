<?php
/**
 * ThreatPulse SOAR - Threat Intelligence Enrichment Service
 * 
 * Central coordinator for IOC enrichment:
 * 1. Validates and normalizes IOC
 * 2. Checks enrichment cache
 * 3. Dispatches lookups across capable threat intelligence providers
 * 4. Persists raw and normalized results with full provenance
 * 5. Aggregates multi-provider reputation assessment (BENIGN, SUSPICIOUS, MALICIOUS, CONFLICTING, UNKNOWN)
 * 6. Updates IOC registry metadata
 * 
 * Safety: Read-only intelligence lookup; NEVER executes response actions or commands.
 */

require_once __DIR__ . '/IocNormalizer.php';
require_once __DIR__ . '/IocValidator.php';
require_once __DIR__ . '/IocRepository.php';
require_once __DIR__ . '/EnrichmentCache.php';
require_once __DIR__ . '/enrichment/ThreatIntelProviderRegistry.php';

class EnrichmentService {
    private ?PDO $pdo;
    private IocRepository $repository;
    private EnrichmentCache $cache;
    private ThreatIntelProviderRegistry $registry;

    public const ASSESSMENT_BENIGN      = 'BENIGN';
    public const ASSESSMENT_SUSPICIOUS  = 'SUSPICIOUS';
    public const ASSESSMENT_MALICIOUS   = 'MALICIOUS';
    public const ASSESSMENT_CONFLICTING = 'CONFLICTING';
    public const ASSESSMENT_UNKNOWN     = 'UNKNOWN';

    public function __construct(
        ?PDO $pdo = null,
        ?ThreatIntelProviderRegistry $registry = null
    ) {
        $this->pdo = $pdo;
        $this->repository = new IocRepository($pdo);
        $this->cache = new EnrichmentCache($this->repository);
        $this->registry = $registry ?: new ThreatIntelProviderRegistry();
    }

    /**
     * Enrich a single IOC across all capable threat intelligence providers.
     * 
     * @param int|array $ioc Either an IOC ID (int) or an array ['ioc_type' => '...', 'ioc_value' => '...']
     * @param bool $forceRefresh Bypass cache if true
     * @param string $actor Submitting identity for audit logging
     * @return array Complete enrichment result with provenance and aggregate assessment
     */
    public function enrichIoc(int|array $ioc, bool $forceRefresh = false, string $actor = 'system'): array {
        // 1. Resolve IOC Record
        if (is_int($ioc)) {
            $iocRecord = $this->repository->find($ioc);
            if (!$iocRecord) {
                throw new InvalidArgumentException("IOC #{$ioc} not found.");
            }
            $iocId = $ioc;
            $iocType = $iocRecord['ioc_type'];
            $iocValue = $iocRecord['ioc_value'];
        } else {
            $iocType = $ioc['ioc_type'] ?? '';
            $iocValue = $ioc['ioc_value'] ?? '';

            $norm = IocNormalizer::normalize($iocType, $iocValue);
            if (!$norm['valid']) {
                throw new InvalidArgumentException("Invalid IOC: " . ($norm['error'] ?? 'MALFORMED'));
            }

            $iocType = $norm['type'];
            $iocValue = $norm['value'];
            $iocId = $this->repository->upsertIoc([
                'ioc_type'  => $iocType,
                'ioc_value' => $iocValue,
            ]);
            $iocRecord = $this->repository->find($iocId);
        }

        // 2. Select Capable Providers
        $capableProviders = $this->registry->getProvidersForType($iocType);
        $providerResults = [];
        $cachedCount = 0;
        $freshCount = 0;
        $failureCount = 0;

        // 3. Query Providers (Checking Cache First)
        foreach ($capableProviders as $provider) {
            $providerName = $provider->getName();

            // Check Cache
            if (!$forceRefresh) {
                $cachedResult = $this->cache->get($iocId, $providerName);
                if ($cachedResult) {
                    $providerResults[$providerName] = $cachedResult;
                    $cachedCount++;
                    continue;
                }
            }

            // Live Provider Lookup
            try {
                $result = $provider->lookup($iocType, $iocValue);
                $this->cache->put($iocId, $result);
                $providerResults[$providerName] = $result;

                if ($result->status === 'SUCCESS') {
                    $freshCount++;
                } else {
                    $failureCount++;
                }

            } catch (Exception $e) {
                $failureResult = new ProviderResult(
                    provider:     $providerName,
                    status:       'FAILED',
                    ioc_type:     $iocType,
                    ioc_value:    $iocValue,
                    raw_response: ['error' => $e->getMessage()],
                    summary:      ['error' => $e->getMessage()],
                    ttl:          300
                );
                $this->cache->put($iocId, $failureResult);
                $providerResults[$providerName] = $failureResult;
                $failureCount++;
            }
        }

        // 4. Multi-Provider Reputation Aggregation
        $assessment = $this->aggregateAssessment($providerResults);

        // 5. Update IOC Record in Database
        if ($this->pdo && $iocId) {
            $maxRep = 0;
            $avgConf = 50;
            $confSum = 0;
            $confCount = 0;
            $malwareFamily = null;
            $threatType = null;

            foreach ($providerResults as $res) {
                if ($res->status === 'SUCCESS') {
                    $maxRep = max($maxRep, $res->reputation);
                    $confSum += $res->confidence;
                    $confCount++;
                    if ($res->malware_family && !$malwareFamily) {
                        $malwareFamily = $res->malware_family;
                    }
                    if (!empty($res->categories[0]) && !$threatType) {
                        $threatType = $res->categories[0];
                    }
                }
            }

            if ($confCount > 0) {
                $avgConf = (int)($confSum / $confCount);
            }

            $stmt = $this->pdo->prepare("
                UPDATE iocs SET 
                    reputation_score = ?, 
                    confidence_score = ?,
                    malware_family = COALESCE(?, malware_family),
                    threat_type = COALESCE(?, threat_type),
                    last_seen = NOW()
                WHERE id = ?
            ");
            $stmt->execute([$maxRep, $avgConf, $malwareFamily, $threatType, $iocId]);
        }

        // 6. Security Audit Log
        $this->auditLog($actor, 'enrich_ioc', "{$iocType}:{$iocValue}", 'success', [
            'ioc_id'        => $iocId,
            'assessment'    => $assessment['assessment'],
            'providers'     => array_keys($providerResults),
            'cached_count'  => $cachedCount,
            'fresh_count'   => $freshCount
        ]);

        return [
            'ioc'           => $this->repository->find($iocId) ?: $iocRecord,
            'assessment'    => $assessment,
            'providers'     => array_map(fn($r) => $r->toArray(), $providerResults),
            'stats'         => [
                'total_providers' => count($capableProviders),
                'cached_results'  => $cachedCount,
                'fresh_results'   => $freshCount,
                'failed_results'  => $failureCount,
            ]
        ];
    }

    /**
     * Deterministically aggregate multi-provider results into a unified IOC assessment.
     * 
     * Categories:
     * - MALICIOUS:   >= 1 provider reports reputation >= 75
     * - SUSPICIOUS:  Provider reports 25 <= reputation < 75
     * - CONFLICTING: At least one provider says highly malicious (>= 75) and another says explicitly benign (0) with high confidence (>= 80)
     * - BENIGN:      Reporting providers report clean / 0
     * - UNKNOWN:     No reporting providers or all lookups failed
     */
    public function aggregateAssessment(array $providerResults): array {
        $successful = array_filter($providerResults, fn($r) => $r->status === 'SUCCESS');
        if (empty($successful)) {
            return [
                'assessment' => self::ASSESSMENT_UNKNOWN,
                'score'      => 0,
                'confidence' => 0,
                'reason'     => 'No threat intelligence providers returned data for this IOC.',
            ];
        }

        $maliciousCount = 0;
        $suspiciousCount = 0;
        $benignHighConfCount = 0;
        $maxReputation = 0;
        $highestConfidence = 0;
        $malwareFamilies = [];

        foreach ($successful as $res) {
            $maxReputation = max($maxReputation, $res->reputation);
            $highestConfidence = max($highestConfidence, $res->confidence);

            if ($res->reputation >= 75) {
                $maliciousCount++;
            } elseif ($res->reputation >= 25) {
                $suspiciousCount++;
            } elseif ($res->reputation === 0 && $res->confidence >= 80) {
                $benignHighConfCount++;
            }

            if ($res->malware_family) {
                $malwareFamilies[] = $res->malware_family;
            }
        }

        // Conflict check
        if ($maliciousCount > 0 && $benignHighConfCount > 0) {
            return [
                'assessment'       => self::ASSESSMENT_CONFLICTING,
                'score'            => $maxReputation,
                'confidence'       => $highestConfidence,
                'reason'           => 'Providers returned contradictory assessments (one reported malicious while another reported explicitly clean with high confidence).',
                'malware_families' => array_unique($malwareFamilies)
            ];
        }

        if ($maliciousCount > 0) {
            return [
                'assessment'       => self::ASSESSMENT_MALICIOUS,
                'score'            => $maxReputation,
                'confidence'       => $highestConfidence,
                'reason'           => "{$maliciousCount} provider(s) classified this IOC as malicious.",
                'malware_families' => array_unique($malwareFamilies)
            ];
        }

        if ($suspiciousCount > 0) {
            return [
                'assessment'       => self::ASSESSMENT_SUSPICIOUS,
                'score'            => $maxReputation,
                'confidence'       => $highestConfidence,
                'reason'           => 'Provider(s) observed suspicious or low-confidence anomaly activity.',
                'malware_families' => array_unique($malwareFamilies)
            ];
        }

        return [
            'assessment'       => self::ASSESSMENT_BENIGN,
            'score'            => 0,
            'confidence'       => $highestConfidence,
            'reason'           => 'All consulted providers report this indicator as clean or unlisted.',
            'malware_families' => []
        ];
    }

    /**
     * Audit log helper without logging credentials or auth headers.
     */
    private function auditLog(string $analyst, string $action, string $target, string $result, array $details): void {
        if (!$this->pdo) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-Enrichment-Engine/1.0';

        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                substr($analyst, 0, 50),
                substr($ip, 0, 45),
                substr($action, 0, 100),
                substr($target, 0, 255),
                $result,
                substr(json_encode($details, JSON_UNESCAPED_SLASHES), 0, 1000),
                substr($ua, 0, 500)
            ]);
        } catch (Exception $e) {}
    }
}
