<?php
/**
 * ThreatPulse SOAR - Feodo Tracker Threat Intelligence Provider
 * 
 * Supports: IPV4 only
 * Feodo Tracker tracks active Botnet C2 servers (Emotet, TrickBot, QakBot, Dridex).
 */

require_once __DIR__ . '/ThreatIntelProvider.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/../IocNormalizer.php';

class FeodoTrackerProvider implements ThreatIntelProvider {
    private HttpClient $http;
    private string $endpoint;

    public function __construct(?HttpClient $http = null, ?string $endpoint = null) {
        $this->http = $http ?: new HttpClient();
        $this->endpoint = $endpoint ?: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
    }

    public function getName(): string {
        return 'FeodoTracker';
    }

    public function getSupportedTypes(): array {
        return [
            IocNormalizer::TYPE_IPV4,
        ];
    }

    public function getRateLimit(): array {
        return [
            'requests_per_minute' => 30,
            'requests_per_hour'   => 500,
        ];
    }

    public function lookup(string $iocType, string $iocValue): ProviderResult {
        if ($iocType !== IocNormalizer::TYPE_IPV4) {
            return new ProviderResult($this->getName(), 'FAILED', $iocType, $iocValue, 0, 0, [], null, null, null, null, ['error' => 'Unsupported IOC type'], date('Y-m-d H:i:s'), 300);
        }

        try {
            $headers = ['User-Agent: ThreatPulse-SOAR/1.0'];
            $response = $this->http->request($this->endpoint, 'GET', $headers, null, $this->getName());
            $statusCode = $response['status'];
            $data = json_decode($response['body'], true);

            if ($statusCode !== 200 || !is_array($data)) {
                return new ProviderResult(
                    provider:     $this->getName(),
                    status:       'FAILED',
                    ioc_type:     $iocType,
                    ioc_value:    $iocValue,
                    raw_response: ['status' => $statusCode, 'body' => substr($response['body'], 0, 500)],
                    summary:      ['error' => "Feodo feed HTTP {$statusCode}"],
                    ttl:          300
                );
            }

            // Search for target IP in blocklist
            $matched = null;
            foreach ($data as $entry) {
                $ip = $entry['ip_address'] ?? ($entry['ip'] ?? '');
                if ($ip === $iocValue) {
                    $matched = $entry;
                    break;
                }
            }

            if ($matched) {
                $malware = $matched['malware'] ?? 'Botnet C2';
                $status = $matched['status'] ?? 'active';
                $reputation = $status === 'active' ? 95 : 75;
                $confidence = 90;

                return new ProviderResult(
                    provider:       $this->getName(),
                    status:         'SUCCESS',
                    ioc_type:       $iocType,
                    ioc_value:      $iocValue,
                    reputation:     $reputation,
                    confidence:     $confidence,
                    categories:     ['Botnet C2'],
                    malware_family: $malware,
                    first_seen:     $matched['first_seen'] ?? null,
                    last_seen:      $matched['last_online'] ?? ($matched['last_seen'] ?? null),
                    raw_response:   $matched,
                    summary:        [
                        'match_found'    => true,
                        'malware_family' => $malware,
                        'c2_status'      => $status,
                        'port'           => $matched['port'] ?? null,
                    ],
                    ttl:            3600
                );
            }

            // Clean / Benign result
            return new ProviderResult(
                provider:     $this->getName(),
                status:       'SUCCESS',
                ioc_type:     $iocType,
                ioc_value:    $iocValue,
                reputation:   0,
                confidence:   70,
                categories:   [],
                raw_response: ['matched' => false],
                summary:      ['status' => 'not_listed', 'message' => 'IP not present on active Feodo blocklist.'],
                ttl:          3600
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
