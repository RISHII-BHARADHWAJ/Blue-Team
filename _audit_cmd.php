<?php
include 'includes/config.php';

if (isset($_SESSION['username']) && isset($_GET['cmd'])) {
    if (function_exists('logSecurityAudit')) {
        logSecurityAudit($_SESSION['username'], 'terminal_command', $_GET['cmd'], 'success', 'Target: ' . ($_GET['target'] ?? 'none'));
    }
}
?>
