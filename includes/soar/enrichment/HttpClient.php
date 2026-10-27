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
    private array $validatedAddresses = [];
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

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new HttpClientSecurityException('URL credentials are not allowed.');
        }
        $host = strtolower(trim($parts['host'], '[]'));
        $ips = [];
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips[] = $host;
        } else {
            if (!preg_match('/^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/D', $host)) {
                throw new HttpClientSecurityException('Invalid hostname.');
            }
            foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $record) {
                $ip = $record['ip'] ?? $record['ipv6'] ?? null;
                if ($ip !== null) $ips[] = $ip;
            }
        }
        if (!$ips) throw new HttpClientSecurityException('Host has no validated public address.');
        foreach ($ips as $ip) self::assertPublicIp($ip);
        $this->validatedAddresses[$host] = $ips;
    }

    public static function assertPublicIp(string $ip): void {
        $packed = @inet_pton($ip);
        if ($packed === false) throw new HttpClientSecurityException('Invalid IP address.');
        if (strlen($packed) === 4) {
            $n = unpack('C4', $packed);
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ||
                $n[1] === 0 || $n[1] === 127 || $n[1] >= 224 ||
                ($n[1] === 100 && $n[2] >= 64 && $n[2] <= 127) ||
                ($n[1] === 169 && $n[2] === 254)) {
                throw new HttpClientSecurityException('Non-public IPv4 address blocked.');
            }
        } else {
            // Accept only global unicast 2000::/3, excluding special-purpose 2001::/23,
            // documentation and 6to4. This rejects mapped IPv4 and transition tricks.
            $hex = bin2hex($packed);
            if ((ord($packed[0]) & 0xe0) !== 0x20 ||
                (substr($hex,0,4) === '2001' && hexdec(substr($hex,4,4)) <= 0x01ff) ||
                str_starts_with($hex,'20010db8') || str_starts_with($hex,'2002') ||
                str_starts_with($hex,'3fff')) {
                throw new HttpClientSecurityException('Non-public IPv6 address blocked.');
            }
        }
    }

    /**
     * Low-level cURL execution with size capping and SSL enforcement.
     */
    private function executeCurl(string $url, string $method, array $headers, ?string $body): array {
        if (!function_exists('curl_init')) {
            throw new HttpClientSecurityException('The cURL extension is required for pinned outbound requests.');
        }

        $parts = parse_url($url);
        $host = strtolower(trim($parts['host'], '[]'));
        $port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);
        $ip = $this->validatedAddresses[$host][0];
        $ch = curl_init();
        // Connect to the address already checked, avoiding a second DNS lookup.
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            curl_setopt($ch, CURLOPT_RESOLVE, ["$host:$port:" . (str_contains($ip, ':') ? "[$ip]" : $ip)]);
        }
        curl_setopt($ch, CURLOPT_PROXY, '');
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        $responseBody = '';
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($handle, string $chunk) use (&$responseBody): int {
            if (strlen($responseBody) + strlen($chunk) > $this->maxResponseBytes) return 0;
            $responseBody .= $chunk;
            return strlen($chunk);
        });
        curl_setopt($ch, CURLOPT_URL, $url);
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

        $ok = curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($ok === false) {
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
