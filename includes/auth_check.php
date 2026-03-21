<?php
// HARDENED SESSION AND HEADERS

// Generate a CSP Nonce
if (empty($_SESSION['csp_nonce'])) {
    $_SESSION['csp_nonce'] = base64_encode(random_bytes(16));
}
$nonce = $_SESSION['csp_nonce'];

// Security Headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Content-Type: text/html; charset=UTF-8");

// Content Security Policy
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-{$nonce}' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' 'nonce-{$nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';");

header_remove("X-Powered-By");
header_remove("Server");

// CSRF TOKEN
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// RATE LIMITER CLASS
class RateLimiter {
    public static function check($action, $limit, $window_seconds) {
        global $pdo;
        $ip = $_SERVER['REMOTE_ADDR'];
        $key = $ip . '_' . $action;

        // Clean up old
        $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL ? SECOND)");
        $stmt->execute([$window_seconds]);

        // Check current
        $stmt = $pdo->prepare("SELECT request_count FROM rate_limits WHERE ip_action_key = ?");
        $stmt->execute([$key]);
        $row = $stmt->fetch();

        if ($row) {
            if ($row['request_count'] >= $limit) {
                // Log the limit hit
                if (function_exists('logSecurityAudit')) {
                   logSecurityAudit($_SESSION['username'] ?? 'guest', 'rate_limit', $action, 'blocked', "Exceeded $limit reqs in $window_seconds s");
                }
                http_response_code(429);
                header("Retry-After: $window_seconds");
                die("429 Too Many Requests. Rate limit exceeded.");
            }
            // Increment
            $stmt = $pdo->prepare("UPDATE rate_limits SET request_count = request_count + 1 WHERE ip_action_key = ?");
            $stmt->execute([$key]);
        } else {
            // Insert new
            $stmt = $pdo->prepare("INSERT INTO rate_limits (ip_action_key, request_count, window_start) VALUES (?, 1, NOW())");
            $stmt->execute([$key]);
        }
    }
}

// Session Fingerprint Validation
if (isset($_SESSION['user_id'])) {
    $current_ip = $_SERVER['REMOTE_ADDR'];
    $current_ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (!isset($_SESSION['ip']) || !isset($_SESSION['ua'])) {
        $_SESSION['ip'] = $current_ip;
        $_SESSION['ua'] = $current_ua;
    } elseif ($_SESSION['ip'] !== $current_ip || $_SESSION['ua'] !== $current_ua) {
        // Hijacking Attempt Detected
        if (function_exists('logSecurityAudit')) {
            logSecurityAudit($_SESSION['username'], 'session_hijack_attempt', $_SERVER['REQUEST_URI'], 'blocked', "IP/UA mismatch. Expected {$_SESSION['ip']}, got $current_ip");
        }
        session_unset();
        session_destroy();
        header('Location: login.php?error=hijack');
        exit;
    }
}

// Helper to log audit events
if (!function_exists('logSecurityAudit')) {
    function logSecurityAudit($analyst, $action, $target, $result, $details) {
        global $pdo;
        if(!$pdo) return;
        $ip = $_SERVER['REMOTE_ADDR'];
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        try {
            $stmt = $pdo->prepare("INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$analyst, $ip, $action, $target, $result, $details, $ua]);
        } catch(PDOException $e) { }
    }
}

?>
