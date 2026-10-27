<?php
include 'includes/config.php';
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign out</title><form method="post"><input type="hidden" name="csrf_token" value="' . htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') . '"><button type="submit">Confirm sign out</button></form></html>';
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
if (!verifyCSRFToken($_POST['csrf_token'] ?? null)) { http_response_code(403); exit('Invalid CSRF token.'); }


if (function_exists('logSecurityAudit') && isset($_SESSION['username'])) {
    logSecurityAudit($_SESSION['username'], 'logout', 'logout.php', 'success', 'User signed out');
}

session_unset();
session_destroy();
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

header('Location: login.php');
exit();
?>