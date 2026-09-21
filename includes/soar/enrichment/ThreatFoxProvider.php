<?php
/**
 * ThreatPulse SOAR - ThreatFox Threat Intelligence Provider
 * 
 * Supports: IPV4, DOMAIN, URL, MD5, SHA256
 * Query endpoint: https://threatfox-api.abuse.ch/api/v1/ (POST search_ioc)
 */

require_once __DIR__ . '/ThreatIntelProvider.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/../IocNormalizer.php';

class ThreatFoxProvider implements ThreatIntelProvider {
    private HttpClient $http;
    private ?string $apiKey;
    private string $endpoint;

    public function __construct(?HttpClient $http = null, ?string $apiKey = null, ?string $endpoint = null) {
        $this->http = $http ?: new HttpClient();
        $this->apiKey = $apiKey ?: (getenv('THREATFOX_API_KEY') ?: null);
        $this->endpoint = $endpoint ?: 'https://threatfox-api.abuse.ch/api/v1/';
    }

    public function getName(): string {
        return 'ThreatFox';
    }

    public function getSupportedTypes(): array {
        return [
            IocNormalizer::TYPE_IPV4,
            IocNormalizer::TYPE_DOMAIN,
            IocNormalizer::TYPE_URL,
            IocNormalizer::TYPE_MD5,
            IocNormalizer::TYPE_SHA256,
        ];
    }

    public function getRateLimit(): array {
        return [
            'requests_per_minute' => 60,
            'requests_per_hour'   => 1000,
        ];
    }

    public function lookup(string $iocType, string $iocValue): ProviderResult {
        $payload = json_encode([
            'query'       => 'search_ioc',
            'search_term' => $iocValue
        ]);

        $headers = ['Content-Type: application/json', 'User-Agent: ThreatPulse-SOAR/1.0'];
        if ($this->apiKey) {
            $headers[] = "Auth-Key: {$this->apiKey}";
        }

        try {
            $response = $this->http->request($this->endpoint, 'POST', $headers, $payload, $this->getName());
            $statusCode = $response['status'];
            $data = json_decode($response['body'], true);

            if ($statusCode === 429) {
                return new ProviderResult($this->getName(), 'RATE_LIMITED', $iocType, $iocValue, 0, 0, [], null, null, null, null, ['error' => 'Rate limit exceeded'], date('Y-m-d H:i:s'), 300);
            }

            if ($statusCode !== 200 || !$data || ($data['query_status'] ?? '') !== 'ok') {
                return new ProviderResult(
                    provider:     $this->getName(),
                    status:       'SUCCESS',
                    ioc_type:     $iocType,
                    ioc_value:    $iocValue,
                    reputation:   0,
                    confidence:   50,
                    categories:   [],
                    raw_response: $data ?: ['body' => $response['body']],
                    summary:      ['status' => 'not_found', 'message' => 'IOC not found in ThreatFox database.'],
                    ttl:          3600
                );
            }

            $entries = $data['data'] ?? [];
            $first = $entries[0] ?? [];

            $confidence = isset($first['confidence_level']) ? (int)$first['confidence_level'] : 75;
            $reputation = $confidence >= 50 ? 85 : 40; // Malicious if confident
            $malware = $first['malware_printable'] ?? ($first['malware'] ?? 'Unknown');
            $threatType = $first['threat_type_desc'] ?? ($first['threat_type'] ?? 'malware');
            $firstSeen = $first['first_seen'] ?? null;
            $lastSeen = $first['last_seen'] ?? null;

            return new ProviderResult(
                provider:       $this->getName(),
                status:         'SUCCESS',
                ioc_type:       $iocType,
                ioc_value:      $iocValue,
                reputation:     $reputation,
                confidence:     $confidence,
                categories:     [$threatType],
                malware_family: $malware,
                first_seen:     $firstSeen,
                last_seen:      $lastSeen,
                raw_response:   $data,
                summary:        [
                    'match_found'    => true,
                    'threat_type'    => $threatType,
                    'malware_family' => $malware,
                    'confidence'     => $confidence
                ],
                ttl:            3600
            );

        } catch (Exception $e) {
            return new ProviderResult(
                provider:     $this->getName(),
                status:       'FAILED',
                ioc_type:     $iocType,
                ioc_value:    $iocValue,
                reputation:   0,
                confidence:   0,
                categories:   [],
                raw_response: ['error' => $e->getMessage()],
                summary:      ['error' => $e->getMessage()],
                ttl:          300
            );
        }
    }
}
