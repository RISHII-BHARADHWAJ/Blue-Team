<?php
/**
 * ThreatPulse SOAR - VirusTotal Threat Intelligence Provider
 * 
 * Supports: IPV4, DOMAIN, URL, MD5, SHA256
 * Endpoint: https://www.virustotal.com/api/v3/
 */

require_once __DIR__ . '/ThreatIntelProvider.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/../IocNormalizer.php';

class VirusTotalProvider implements ThreatIntelProvider {
    private HttpClient $http;
    private ?string $apiKey;
    private string $baseUrl;

    public function __construct(?HttpClient $http = null, ?string $apiKey = null, ?string $baseUrl = null) {
        $this->http = $http ?: new HttpClient();
        $this->apiKey = $apiKey ?: (getenv('VIRUSTOTAL_API_KEY') ?: null);
        $this->baseUrl = $baseUrl ?: 'https://www.virustotal.com/api/v3/';
    }

    public function getName(): string {
        return 'VirusTotal';
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
            'requests_per_minute' => 4,   // Free API rate limit
            'requests_per_hour'   => 240,
        ];
    }

    public function lookup(string $iocType, string $iocValue): ProviderResult {
        if (!in_array($iocType, $this->getSupportedTypes(), true)) {
            return new ProviderResult($this->getName(), 'FAILED', $iocType, $iocValue, 0, 0, [], null, null, null, null, ['error' => 'Unsupported IOC type'], date('Y-m-d H:i:s'), 300);
        }

        if (empty($this->apiKey)) {
            return new ProviderResult(
                provider:     $this->getName(),
                status:       'SUCCESS',
                ioc_type:     $iocType,
                ioc_value:    $iocValue,
                reputation:   0,
                confidence:   50,
                categories:   [],
                raw_response: ['note' => 'VirusTotal API key not configured; returned passive baseline.'],
                summary:      ['status' => 'unconfigured_key'],
                ttl:          3600
            );
        }

        // Build type-specific endpoint URL
        $path = match ($iocType) {
            IocNormalizer::TYPE_IPV4   => "ip_addresses/{$iocValue}",
            IocNormalizer::TYPE_DOMAIN => "domains/{$iocValue}",
            IocNormalizer::TYPE_URL    => "urls/" . rtrim(strtr(base64_encode($iocValue), '+/', '-_'), '='),
            IocNormalizer::TYPE_MD5,
            IocNormalizer::TYPE_SHA256 => "files/{$iocValue}",
            default                    => null
        };

        if (!$path) {
            return new ProviderResult($this->getName(), 'FAILED', $iocType, $iocValue, 0, 0, [], null, null, null, null, ['error' => 'Invalid path resolution'], date('Y-m-d H:i:s'), 300);
        }

        $url = rtrim($this->baseUrl, '/') . '/' . $path;
        $headers = [
            "x-apikey: {$this->apiKey}",
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

            if ($statusCode === 404) {
                return new ProviderResult(
                    provider:     $this->getName(),
                    status:       'SUCCESS',
                    ioc_type:     $iocType,
                    ioc_value:    $iocValue,
                    reputation:   0,
                    confidence:   50,
                    raw_response: ['not_found' => true],
                    summary:      ['status' => 'not_found', 'message' => 'IOC not found in VirusTotal database.'],
                    ttl:          3600
                );
            }

            if ($statusCode !== 200 || !isset($data['data']['attributes'])) {
                return new ProviderResult(
                    provider:     $this->getName(),
                    status:       'FAILED',
                    ioc_type:     $iocType,
                    ioc_value:    $iocValue,
                    raw_response: $data ?: ['body' => substr($response['body'], 0, 500)],
                    summary:      ['error' => "VirusTotal returned HTTP {$statusCode}"],
                    ttl:          300
                );
            }

            $attrs = $data['data']['attributes'];
            $stats = $attrs['last_analysis_stats'] ?? [];
            $malicious = (int)($stats['malicious'] ?? 0);
            $suspicious = (int)($stats['suspicious'] ?? 0);
            $totalEngines = array_sum($stats) ?: 70;

            $reputation = min(100, (int)(($malicious * 10) + ($suspicious * 5)));
            $confidence = min(100, max(50, (int)(($totalEngines / 70) * 100)));

            return new ProviderResult(
                provider:       $this->getName(),
                status:         'SUCCESS',
                ioc_type:       $iocType,
                ioc_value:      $iocValue,
                reputation:     $reputation,
                confidence:     $confidence,
                categories:     $malicious > 0 ? ['Malicious Engine Detection'] : ['Clean'],
                malware_family: $attrs['popular_threat_classification']['suggested_threat_label'] ?? null,
                first_seen:     isset($attrs['first_submission_date']) ? date('Y-m-d H:i:s', $attrs['first_submission_date']) : null,
                last_seen:      isset($attrs['last_analysis_date']) ? date('Y-m-d H:i:s', $attrs['last_analysis_date']) : null,
                raw_response:   $data,
                summary:        [
                    'malicious_detections'  => $malicious,
                    'suspicious_detections' => $suspicious,
                    'total_engines'         => $totalEngines,
                ],
                ttl:            $iocType === IocNormalizer::TYPE_MD5 || $iocType === IocNormalizer::TYPE_SHA256 ? 86400 : 21600
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
