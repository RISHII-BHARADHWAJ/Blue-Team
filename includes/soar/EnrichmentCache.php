<?php
/**
 * ThreatPulse SOAR - Threat Intelligence Enrichment Cache
 * 
 * Manages caching and expiration for provider enrichment results
 * using the `enrichment_results` database table.
 * 
 * Default TTL Policies:
 * - IPV4 / IPV6: 1 hour (3600s)
 * - DOMAIN:      6 hours (21600s)
 * - URL:         6 hours (21600s)
 * - MD5 / SHA256: 24 hours (86400s)
 * - EMAIL:       24 hours (86400s)
 */

require_once __DIR__ . '/IocNormalizer.php';
require_once __DIR__ . '/IocRepository.php';
require_once __DIR__ . '/enrichment/ThreatIntelProvider.php';

class EnrichmentCache {
    private IocRepository $repository;

    private const DEFAULT_TTLS = [
        IocNormalizer::TYPE_IPV4   => 3600,   // 1 hour
        IocNormalizer::TYPE_IPV6   => 3600,   // 1 hour
        IocNormalizer::TYPE_DOMAIN => 21600,  // 6 hours
        IocNormalizer::TYPE_URL    => 21600,  // 6 hours
        IocNormalizer::TYPE_MD5    => 86400,  // 24 hours
        IocNormalizer::TYPE_SHA256 => 86400,  // 24 hours
        IocNormalizer::TYPE_EMAIL  => 86400,  // 24 hours
    ];

    public function __construct(?IocRepository $repository = null) {
        $this->repository = $repository ?: new IocRepository(null);
    }

    /**
     * Resolve default TTL for an IOC type.
     */
    public function getTtlForType(string $iocType): int {
        return self::DEFAULT_TTLS[strtoupper(trim($iocType))] ?? 3600;
    }

    /**
     * Get non-expired cached enrichment result for an IOC and provider.
     */
    public function get(int $iocId, string $provider): ?ProviderResult {
        $row = $this->repository->getCachedEnrichment($iocId, $provider);
        if (!$row) return null;

        $parsed = is_array($row['parsed_summary']) ? $row['parsed_summary'] : [];
        $raw = is_array($row['raw_response']) ? $row['raw_response'] : [];

        return new ProviderResult(
            provider:       $row['provider'],
            status:         $row['status'],
            ioc_type:       $parsed['ioc_type'] ?? 'UNKNOWN',
            ioc_value:      $parsed['ioc_value'] ?? '',
            reputation:     (int)($parsed['reputation'] ?? 0),
            confidence:     (int)($parsed['confidence'] ?? 50),
            categories:     $parsed['categories'] ?? [],
            malware_family: $parsed['malware_family'] ?? null,
            first_seen:     $parsed['first_seen'] ?? null,
            last_seen:      $parsed['last_seen'] ?? null,
            raw_response:   $raw,
            summary:        $parsed['summary'] ?? $parsed,
            retrieved_at:   $row['created_at'],
            ttl:            strtotime($row['cached_until']) - strtotime($row['created_at']),
            cached:         true
        );
    }

    /**
     * Store a provider result in the cache table.
     */
    public function put(int $iocId, ProviderResult $result): void {
        $ttl = $result->ttl ?: $this->getTtlForType($result->ioc_type);
        $cachedUntil = date('Y-m-d H:i:s', time() + $ttl);

        $summary = [
            'ioc_type'       => $result->ioc_type,
            'ioc_value'      => $result->ioc_value,
            'reputation'     => $result->reputation,
            'confidence'     => $result->confidence,
            'categories'     => $result->categories,
            'malware_family' => $result->malware_family,
            'first_seen'     => $result->first_seen,
            'last_seen'      => $result->last_seen,
            'summary'        => $result->summary,
        ];

        $this->repository->saveEnrichmentResult(
            $iocId,
            $result->provider,
            $result->status,
            $result->raw_response,
            $summary,
            $cachedUntil
        );
    }
}
