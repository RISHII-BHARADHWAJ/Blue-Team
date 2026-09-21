<?php
/**
 * ThreatPulse SOAR - Hardened Threat Intelligence HTTP Client
 * 
 * Features:
 * 1. Strict SSRF Protection (Hostname DNS resolution verification against private/cloud metadata ranges)
 * 2. Strict Timeouts (Connect: 3s, Total: 10s, Max Size: 1MB)
 * 3. Exponential Backoff Retries (on 429, 502, 503, 504, timeout)
 * 4. Circuit Breaker (CLOSED -> OPEN -> HALF_OPEN)
 * 5. Safe Error Handling without leaking secret tokens
 */

class HttpClientSecurityException extends RuntimeException {}

class HttpClient {
    private int $connectTimeout;
    private int $totalTimeout;
    private int $maxResponseBytes;
    private int $maxRetries;

    /**
     * Circuit breaker state tracking per provider/host:
     * ['state' => 'CLOSED'|'OPEN'|'HALF_OPEN', 'failures' => int, 'opened_at' => int]
     */
    private static array $circuitBreakers = [];
    public const CIRCUIT_COOLDOWN = 60; // 60 seconds

    public function __construct(
        int $connectTimeout = 3,
        int $totalTimeout = 10,
        int $maxResponseBytes = 1048576, // 1MB
        int $maxRetries = 2
    ) {
        $this->connectTimeout = $connectTimeout;
        $this->totalTimeout = $totalTimeout;
        $this->maxResponseBytes = $maxResponseBytes;
        $this->maxRetries = $maxRetries;
    }

    /**
     * Perform an SSRF-safe HTTP request with circuit breaker and retry logic.
     * 
     * @param string $url Target endpoint URL
     * @param string $method HTTP method (GET, POST)
     * @param array $headers Request headers
     * @param ?string $body Request payload
     * @param string $providerName Name of provider for circuit breaking
     * @return array ['status' => int, 'body' => string, 'headers' => array]
     */
    public function request(
        string $url,
        string $method = 'GET',
        array $headers = [],
        ?string $body = null,
        string $providerName = 'default'
    ): array {
        // 1. Check Circuit Breaker
        $this->assertCircuitAvailable($providerName);

        // 2. Validate URL & SSRF Check
        $this->validateUrlSsrf($url);

        // 3. Execution with Retries
        $attempt = 0;
        $lastException = null;

        while ($attempt <= $this->maxRetries) {
            try {
                $response = $this->executeCurl($url, $method, $headers, $body);
                $statusCode = $response['status'];

                // Check for transient server errors that qualify for retry
                if (in_array($statusCode, [429, 502, 503, 504], true)) {
                    if ($attempt < $this->maxRetries) {
                        $attempt++;
                        usleep((int)(pow(2, $attempt) * 200000)); // Exponential backoff (400ms, 800ms)
                        continue;
                    }
                }

                // Success or normal response
                $this->recordCircuitSuccess($providerName);
                return $response;

            } catch (Exception $e) {
                $lastException = $e;
                if ($attempt < $this->maxRetries) {
                    $attempt++;
                    usleep((int)(pow(2, $attempt) * 200000));
                    continue;
                }
                break;
            }
        }

        $this->recordCircuitFailure($providerName);
        throw $lastException ?: new RuntimeException("HTTP Request failed after {$this->maxRetries} retries.");
    }

    /**
     * Assert URL is valid and target host does not resolve to private/link-local/metadata IPs.
     */
    public function validateUrlSsrf(string $url): void {
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            throw new HttpClientSecurityException("Invalid or malformed URL: $url");
        }

        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new HttpClientSecurityException("Unsupported URL scheme '$scheme'. Only HTTP/HTTPS permitted.");
        }

        $host = strtolower($parts['host']);

        // Check literal hostnames
        if (in_array($host, ['localhost', '127.0.0.1', '::1', '169.254.169.254', 'metadata.google.internal'], true)) {
            throw new HttpClientSecurityException("Access to loopback/metadata host '$host' is blocked.");
        }

        // If host is an IP, check directly
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $this->assertPublicIp($host);
            return;
        }

        // Resolve DNS and verify all returned addresses
        $resolvedIps = @dns_get_record($host, DNS_A + DNS_AAAA);
        if (!empty($resolvedIps)) {
            foreach ($resolvedIps as $rec) {
                $ip = $rec['ip'] ?? ($rec['ipv6'] ?? null);
                if ($ip) {
                    $this->assertPublicIp($ip);
                }
            }
        }
    }

    /**
     * Verify that an IP address is publicly routable and not in private/link-local ranges.
     */
    public static function assertPublicIp(string $ip): void {
        // IPv4 Checks
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new HttpClientSecurityException("SSRF blocked: IP '$ip' belongs to a private or reserved network range.");
            }
            if (str_starts_with($ip, '127.') || str_starts_with($ip, '169.254.') || str_starts_with($ip, '100.64.')) {
                throw new HttpClientSecurityException("SSRF blocked: IP '$ip' is loopback or link-local.");
            }
            return;
        }

        // IPv6 Checks
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if ($ip === '::1' || str_starts_with($ip, 'fe80:') || str_starts_with($ip, 'fc00:') || str_starts_with($ip, 'fd00:')) {
                throw new HttpClientSecurityException("SSRF blocked: IPv6 '$ip' is loopback, unique local, or link-local.");
            }
            return;
        }

        throw new HttpClientSecurityException("Invalid IP address: '$ip'");
    }

    /**
     * Low-level cURL execution with size capping and SSL enforcement.
     */
    private function executeCurl(string $url, string $method, array $headers, ?string $body): array {
        if (!function_exists('curl_init')) {
            // Fallback stream context if cURL not available
            return $this->executeStreamContext($url, $method, $headers, $body);
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->totalTimeout);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // Prevent open redirect SSRF bypass

        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        if ($body !== null && ($method === 'POST' || $method === 'PUT')) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $responseBody = curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false && $statusCode === 0) {
            throw new RuntimeException("cURL execution error: $curlError");
        }

        if (strlen((string)$responseBody) > $this->maxResponseBytes) {
            throw new RuntimeException("Response size exceeded maximum allowed limit of {$this->maxResponseBytes} bytes.");
        }

        return [
            'status'  => (int)$statusCode,
            'body'    => (string)$responseBody,
            'headers' => []
        ];
    }

    /**
     * Fallback stream context executor.
     */
    private function executeStreamContext(string $url, string $method, array $headers, ?string $body): array {
        $headerLines = implode("\r\n", $headers);
        $opts = [
            'http' => [
                'method'        => $method,
                'header'        => $headerLines,
                'content'       => $body,
                'timeout'       => $this->totalTimeout,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ]
        ];

        $ctx = stream_context_create($opts);
        $result = @file_get_contents($url, false, $ctx);
        $status = 200;

        if (isset($http_response_header) && isset($http_response_header[0])) {
            if (preg_match('/HTTP\/\S+\s+(\d+)/', $http_response_header[0], $m)) {
                $status = (int)$m[1];
            }
        }

        return [
            'status'  => $status,
            'body'    => (string)$result,
            'headers' => $http_response_header ?? []
        ];
    }

    /**
     * Circuit Breaker State Machine checks.
     */
    private function assertCircuitAvailable(string $provider): void {
        if (!isset(self::$circuitBreakers[$provider])) {
            self::$circuitBreakers[$provider] = ['state' => 'CLOSED', 'failures' => 0, 'opened_at' => 0];
        }

        $cb = self::$circuitBreakers[$provider];
        if ($cb['state'] === 'OPEN') {
            if (time() - $cb['opened_at'] >= self::CIRCUIT_COOLDOWN) {
                // Transition to HALF_OPEN to test recovery
                self::$circuitBreakers[$provider]['state'] = 'HALF_OPEN';
            } else {
                throw new RuntimeException("Circuit breaker for provider '$provider' is OPEN (cooldown in progress).");
            }
        }
    }

    private function recordCircuitSuccess(string $provider): void {
        self::$circuitBreakers[$provider] = ['state' => 'CLOSED', 'failures' => 0, 'opened_at' => 0];
    }

    private function recordCircuitFailure(string $provider): void {
        if (!isset(self::$circuitBreakers[$provider])) {
            self::$circuitBreakers[$provider] = ['state' => 'CLOSED', 'failures' => 0, 'opened_at' => 0];
        }

        self::$circuitBreakers[$provider]['failures']++;
        if (self::$circuitBreakers[$provider]['failures'] >= 3) {
            self::$circuitBreakers[$provider]['state'] = 'OPEN';
            self::$circuitBreakers[$provider]['opened_at'] = time();
        }
    }

    public static function resetCircuitBreakers(): void {
        self::$circuitBreakers = [];
    }
}
