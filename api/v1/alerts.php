<?php
/**
 * ThreatPulse SOAR - Alert Ingestion REST API Endpoint
 * 
 * Endpoint: POST /api/v1/alerts.php
 * 
 * Accepts raw security alerts from external sensors, log shippers, or webhooks.
 * Validates, normalizes, and deduplicates the incoming alert.
 * 
 * Authentication:
 * 1. Active analyst session (CYBERTECH_SECURE_SESSION)
 * 2. Authorization: Bearer <API_KEY> (machine-to-machine)
 * 
 * Response Contract:
 * - 202 Accepted: Alert validated, normalized, and accepted (non-duplicate)
 * - 200 OK: Alert validated, normalized, but suppressed as duplicate
 * - 401 Unauthorized: Missing or invalid credentials
 * - 405 Method Not Allowed: Non-POST requests
 * - 413 Payload Too Large: Body > 64KB
 * - 415 Unsupported Media Type: Non-JSON Content-Type
 * - 422 Unprocessable Content: Validation error
 * - 429 Too Many Requests: Rate limit exceeded
 * - 500 Internal Server Error: Generic safe error
 * - 503 Service Unavailable: Server missing required API key configuration
 */

// Strict Response Headers
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

// 1. Method Validation
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    echo json_encode([
        'success' => false,
        'error'   => 'method_not_allowed',
        'message' => 'Only POST requests are supported on this endpoint.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// 2. Content-Type Validation
$contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
if (!str_contains(strtolower($contentType), 'application/json')) {
    http_response_code(415);
    echo json_encode([
        'success' => false,
        'error'   => 'unsupported_media_type',
        'message' => 'Content-Type must be application/json.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// 3. Payload Size Limitation (Max 64KB)
$rawBody = file_get_contents('php://input');
if ($rawBody === false || strlen($rawBody) > 65536) {
    http_response_code(413);
    echo json_encode([
        'success' => false,
        'error'   => 'payload_too_large',
        'message' => 'Alert payload exceeds maximum allowed size of 64KB.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// 4. Initialize Database & Session
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SiemSoarAlertPipeline.php';
require_once __DIR__ . '/../../includes/soar/SoarCsrf.php';

session_name('CYBERTECH_SECURE_SESSION');
if (session_status() === PHP_SESSION_NONE) {
    @session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict', 'use_strict_mode' => true]);
}

// 5. Authentication Verification
$actor = null;
$isAuthenticated = false;
$authenticationMethod = null;

// Check A: Session Authentication
if (!empty($_SESSION['analyst']) || !empty($_SESSION['user_id'])) {
    $actor = $_SESSION['analyst'] ?? ('user_' . $_SESSION['user_id']);
    $isAuthenticated = true;
    $authenticationMethod = 'session';
}

// Check B: Authorization Bearer Token
if (!$isAuthenticated) {
    // Reject tokens in query parameters, cookies, or body
    if (isset($_GET['api_key']) || isset($_GET['token']) || isset($_POST['api_key'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error'   => 'invalid_auth_location',
            'message' => 'API keys must be transmitted exclusively via Authorization: Bearer <token> headers.'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+([a-zA-Z0-9_\-\.]{16,128})$/i', trim($authHeader), $matches)) {
        $providedToken = $matches[1];

        // Resolve system API key strictly from the environment.
        // No hardcoded fallback: if the env var is unset, the server is
        // misconfigured and must refuse bearer-token auth entirely rather
        // than silently accept a known default secret.
        $configuredKey = getenv('THREATPULSE_API_KEY');

        if ($configuredKey === false || $configuredKey === '') {
            try {
                $stmt = $pdo->prepare("
                    INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    'system',
                    substr($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', 0, 45),
                    'api_alert_ingest',
                    'api/v1/alerts.php',
                    'blocked',
                    'Server misconfiguration: THREATPULSE_API_KEY environment variable not set',
                    substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500)
                ]);
            } catch (Exception $e) {}

            http_response_code(503);
            echo json_encode([
                'success' => false,
                'error'   => 'service_misconfigured',
                'message' => 'API key authentication is not available. Server is missing required configuration.'
            ], JSON_UNESCAPED_SLASHES);
            exit;
        }

        if (hash_equals(hash('sha256', $configuredKey), hash('sha256', $providedToken))) {
            $actor = 'api_sensor_' . substr(hash('sha256', $providedToken), 0, 8);
            $isAuthenticated = true;
            $authenticationMethod = 'bearer';
        }
    }
}

if (!$isAuthenticated) {
    // Audit failed unauthenticated access attempt
    try {
        $stmt = $pdo->prepare("
            INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            'unauthenticated',
            substr($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', 0, 45),
            'api_alert_ingest',
            'api/v1/alerts.php',
            'blocked',
            'Missing or invalid authentication token',
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500)
        ]);
    } catch (Exception $e) {}

    http_response_code(401);
    header('WWW-Authenticate: Bearer realm="ThreatPulse SOAR API"');
    echo json_encode([
        'success' => false,
        'error'   => 'unauthorized',
        'message' => 'Authentication required. Provide valid analyst session or Authorization: Bearer <API_KEY> header.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// Browser sessions require a CSRF token; verified bearer sensors do not.
SoarCsrf::enforce(['auth_method' => $authenticationMethod]);

// 6. Rate Limiting (120 requests per 60 seconds per IP/Actor)
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$rateKey = 'api_ingest_' . $clientIp;

try {
    // Cleanup old rate limit records
    $pdo->prepare("DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 60 SECOND)")->execute();
    
    $stmt = $pdo->prepare("SELECT request_count FROM rate_limits WHERE ip_action_key = ?");
    $stmt->execute([$rateKey]);
    $rateRow = $stmt->fetch();

    if ($rateRow && $rateRow['request_count'] >= 120) {
        http_response_code(429);
        header('Retry-After: 60');
        echo json_encode([
            'success' => false,
            'error'   => 'rate_limit_exceeded',
            'message' => 'Rate limit exceeded. Maximum 120 requests per minute.'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($rateRow) {
        $pdo->prepare("UPDATE rate_limits SET request_count = request_count + 1 WHERE ip_action_key = ?")->execute([$rateKey]);
    } else {
        $pdo->prepare("INSERT INTO rate_limits (ip_action_key, request_count, window_start) VALUES (?, 1, NOW())")->execute([$rateKey]);
    }
} catch (Exception $e) {
    // Non-blocking rate limit fallback
}

// 7. Parse JSON Body
$data = json_decode($rawBody, true);
if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error'   => 'invalid_json',
        'message' => 'Malformed JSON payload: ' . json_last_error_msg()
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// 8. Ingest, persist legacy SIEM record, and correlate to a SOAR incident
try {
    $service = new SiemSoarAlertPipeline($pdo);
    $result = $service->ingest($data, $actor);

    if (!$result['success']) {
        http_response_code(422);
        echo json_encode($result, JSON_UNESCAPED_SLASHES);
        exit;
    }

    if (!empty($result['duplicate'])) {
        http_response_code(200); // 200 OK for suppressed duplicate
        echo json_encode($result, JSON_UNESCAPED_SLASHES);
        exit;
    }

    // 202 Accepted only after the SIEM event and correlation are committed
    http_response_code(202);
    echo json_encode($result, JSON_UNESCAPED_SLASHES);
    exit;

} catch (Throwable $e) {
    error_log('SOAR alert pipeline failed: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error'   => 'internal_server_error',
        'message' => 'An unexpected internal error occurred while processing the alert.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}