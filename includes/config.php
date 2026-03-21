<?php
// Session Hardening
ini_set('session.cookie_lifetime', 0);
ini_set('session.cookie_secure', 0); // Disable ONLY IF env doesn't support HTTPS (e.g., local Docker HTTP)
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.gc_maxlifetime', 1800);

session_name('CYBERTECH_SECURE_SESSION');
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$db_host = getenv('DB_HOST') ? getenv('DB_HOST') : "localhost";
$db_user = "redteam_user";
$db_pass = "root";
$db_name = "cybertech_db";

// PDO Migration
try {
    $dsn = "mysql:host=$db_host;dbname=$db_name;charset=utf8mb4";
    $pdo = new PDO($dsn, $db_user, $db_pass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false, // CRITICAL FIX
    ]);
} catch (PDOException $e) {
    die("Database Connection Error. Please contact admin.");
}

// Legacy connection stub removed - strictly enforcing PDO

// Include other helpers
@include_once __DIR__ . '/security.php';
@include_once __DIR__ . '/waf.php';

// Include auth checks & gateway
include_once __DIR__ . '/auth_check.php';

// Legacy logActivity mapping to new format loosely
if (!function_exists('logActivity')) {
    function logActivity($action, $details = "") {
        global $pdo;
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'];
        $details = substr($details, 0, 500);

        try {
            $stmt = $pdo->prepare("INSERT INTO activity_logs (timestamp, ip_address, user_agent, action, details, request_uri) VALUES (NOW(), ?, ?, ?, ?, ?)");
            $stmt->execute([$ip, $user_agent, $action, $details, $request_uri]);
        } catch (PDOException $e) { }
    }
}

if (!function_exists('getUserCredits')) {
    function getUserCredits($user_id) {
        global $pdo;
        $stmt = $pdo->prepare("SELECT credits FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $row = $stmt->fetch();
        return $row ? $row['credits'] : 0;
    }
}
?>