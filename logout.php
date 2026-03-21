<?php
include 'includes/config.php';

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