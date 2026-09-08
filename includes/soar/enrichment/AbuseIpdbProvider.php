<?php
/**
 * ThreatPulse SOAR - AbuseIPDB Threat Intelligence Provider
 * 
 * Supports: IPV4, IPV6
 * Endpoint: https://api.abuseipdb.com/api/v2/check
 */

require_once __DIR__ . '/ThreatIntelProvider.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/../IocNormalizer.php';

class AbuseIpdbProvider implements ThreatIntelProvider {
    private HttpClient $http;
    private ?string $apiKey;
    private string $endpoint;

    public function __construct(?HttpClient $http = null, ?string $apiKey = null, ?string $endpoint = null) {
        $this->http = $http ?: new HttpClient();
        $this->apiKey = $apiKey ?: (getenv('ABUSEIPDB_API_KEY') ?: null);
        $this->endpoint = $endpoint ?: 'https://api.abuseipdb.com/api/v2/check';
    }

    public function getName(): string {
        return 'AbuseIPDB';
    }

    public function getSupportedTypes(): array {
        return [
            IocNormalizer::TYPE_IPV4,
            IocNormalizer::TYPE_IPV6,
        ];
    }

    public function getRateLimit(): array {
        return [
            'requests_per_minute' => 60,
            'requests_per_hour'   => 1000,
        ];
    }

    public function lookup(string $iocType, string $iocValue): ProviderResult {
        if (!in_array($iocType, [IocNormalizer::TYPE_IPV4, IocNormalizer::TYPE_IPV6], true)) {
            return new ProviderResult($this->getName(), 'FAILED', $iocType, $iocValue, 0, 0, [], null, null, null, null, ['error' => 'Unsupported IOC type'], date('Y-m-d H:i:s'), 300);
        }

        if (empty($this->apiKey)) {
            // Unconfigured API key simulation / mock response
            return new ProviderResult(
                provider:     $this->getName(),
                status:       'SUCCESS',
                ioc_type:     $iocType,
                ioc_value:    $iocValue,
                reputation:   0,
                confidence:   50,
                categories:   [],
                raw_response: ['note' => 'AbuseIPDB API key not configured; returned passive baseline.'],
                summary:      ['status' => 'unconfigured_key'],
                ttl:          3600
            );
        }

        $url = $this->endpoint . '?ipAddress=' . urlencode($iocValue) . '&maxAgeInDays=90';
        $headers = [
            "Key: {$this->apiKey}",
            'Accept: application/json',
            'User-Agent: ThreatPulse-SOAR/1.0'
        ];

        try {
            $response = $this->http->request($url, 'GET', $headers, null, $this->getName());
            $statusCode = $response['status'];
            $data = json_decode($response['body'], true);

            if ($statusCode === 429) {
                return new ProviderResult($this->getName(), 'RATE_LIMITED', $iocType, $iocValue, 0, 0, [], null, null, null, null, ['error' => 'Rate limit exceeded'], date('Y-m-d H:i:s'), 300);
            }

            if ($statusCode !== 200 || !isset($data['data'])) {
                return new ProviderResult(
                    provider:     $this->getName(),
                    status:       'FAILED',
                    ioc_type:     $iocType,
                    ioc_value:    $iocValue,
                    raw_response: $data ?: ['body' => substr($response['body'], 0, 500)],
                    summary:      ['error' => "AbuseIPDB returned HTTP {$statusCode}"],
                    ttl:          300
                );
            }

            $info = $data['data'];
            $score = (int)($info['abuseConfidenceScore'] ?? 0);
            $reports = (int)($info['totalReports'] ?? 0);
            $country = $info['countryCode'] ?? null;
            $usage = $info['usageType'] ?? 'Unknown';
            $lastReported = $info['lastReportedAt'] ?? null;

            return new ProviderResult(
                provider:       $this->getName(),
                status:         'SUCCESS',
                ioc_type:       $iocType,
                ioc_value:      $iocValue,
                reputation:     $score,
                confidence:     min(100, max(50, $reports * 5)),
                categories:     [$usage],
                malware_family: null,
                first_seen:     null,
                last_seen:      $lastReported,
                raw_response:   $data,
                summary:        [
                    'abuse_confidence_score' => $score,
                    'total_reports'          => $reports,
                    'country'                => $country,
                    'usage_type'             => $usage,
                ],
                ttl:            3600
            );

        } catch (Exception $e) {
            return new ProviderResult(
                provider:     $this->getName(),
                status:       'FAILED',
                ioc_type:     $iocType,
                ioc_value:    $iocValue,
                raw_response: ['error' => $e->getMessage()],
                summary:      ['error' => $e->getMessage()],
                ttl:          300
            );
        }
    }
}
