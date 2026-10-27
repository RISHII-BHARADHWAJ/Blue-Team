<?php
/** Shared browser session policy. Forwarded headers are not trusted by default. */
function tpStartSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_name('CYBERTECH_SECURE_SESSION');
        session_start([
            'cookie_httponly' => true, 'cookie_samesite' => 'Strict',
            'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || getenv('SESSION_COOKIE_SECURE') === '1',
            'use_strict_mode' => true, 'use_only_cookies' => true,
            'cookie_lifetime' => 0, 'gc_maxlifetime' => 1800,
        ]);
    }
    $now = time();
    if (!empty($_SESSION['user_id']) || !empty($_SESSION['analyst'])) {
        if (($now - ($_SESSION['last_activity'] ?? $now)) >= 1800 ||
            ($now - ($_SESSION['authenticated_at'] ?? $now)) >= 28800) {
            $_SESSION = [];
            session_regenerate_id(true);
        } else {
            $_SESSION['authenticated_at'] ??= $now;
            $_SESSION['last_activity'] = $now;
        }
    }
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header_remove('X-Powered-By');
}
