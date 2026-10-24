<?php
include 'includes/config.php';

// Rate limit login endpoint (5 requests per 5 minutes = 300s)
RateLimiter::check('login', 50, 300);

if (isset($_SESSION['user_id'])) {
    header('Location: soc.php');
    exit();
}

$error = (isset($_GET['error']) && $_GET['error'] == 'hijack') ? "Session Hijack Attempt Detected. You have been logged out." : "";

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // CSRF Check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        if (function_exists('logSecurityAudit')) logSecurityAudit('guest', 'login_csrf_fail', 'login.php', 'blocked', 'CSRF token mismatch');
        http_response_code(403);
        die('CSRF validation failed.');
    }

    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // Fetch user
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user) {
        // Check lockout
        if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
            $error = "Account locked until " . $user['locked_until'] . ". Try again later.";
            if (function_exists('logSecurityAudit')) logSecurityAudit($username, 'login', 'login.php', 'blocked', 'Account is locked');
        } else {
            // Verify password
            if (password_verify($password, $user['password'])) {
                // Success
                session_regenerate_id(true); // Prevent session fixation
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['analyst'] = $user['username']; // For new dashboard compatibility
                $_SESSION['role'] = $user['role'];
                $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
                $_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                
                // Clear failures
                $stmt = $pdo->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?");
                $stmt->execute([$user['id']]);

                if (function_exists('logSecurityAudit')) logSecurityAudit($username, 'login', 'login.php', 'success', 'User authenticated');

                header('Location: soc.php');
                exit();
            } else {
                // Failure
                $attempts = $user['failed_attempts'] + 1;
                $lock_query = "UPDATE users SET failed_attempts = ?";
                $params = [$attempts];
                
                if ($attempts >= 5) {
                    $lock_query .= ", locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE)";
                    if (function_exists('logSecurityAudit')) logSecurityAudit($username, 'account_lockout', 'login.php', 'blocked', '5 failed login attempts');
                }
                $lock_query .= " WHERE id = ?";
                $params[] = $user['id'];
                
                $stmt = $pdo->prepare($lock_query);
                $stmt->execute($params);
                
                $error = "Invalid credentials.";
                if (function_exists('logSecurityAudit')) logSecurityAudit($username, 'login', 'login.php', 'failure', 'Invalid password');
            }
        }
    } else {
        // User not found (simulate same timing to prevent enumeration slightly)
        password_verify($password, '$argon2id$v=19$m=65536,t=4,p=1$UWNmZmFFYzFsckpWU3NKbQ$Tz59ZHHOe+bzpT+HeUINIgMwTae+dHMHsIqIAhrjLBQ');
        $error = "Invalid credentials.";
        if (function_exists('logSecurityAudit')) logSecurityAudit($username, 'login', 'login.php', 'failure', 'User not found');
    }
}

?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · ThreatPulse</title><link rel="stylesheet" href="assets/css/design-system.css"><link rel="stylesheet" href="assets/css/login.css"></head><body class="tp-login">
<section class="tp-login-story"><a class="login-brand" href="login.php"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M3 17h7l4-10 6 19 4-9h5"/></svg>ThreatPulse</a><span class="login-edition">SECURITY OPERATIONS / LAB EDITION</span><div class="login-message"><span class="login-kicker">Clarity under pressure.</span><h1>Every signal.<br>A better<br><em>decision.</em></h1><p>From the first event to the final handoff.<br>One workspace for the investigation.</p></div><div class="login-signal" aria-hidden="true"><svg viewBox="0 0 600 150"><path d="M0 75h150l35-45 45 90 55-120 65 150 40-75h210"/></svg></div><div class="login-story-footer">01 / OBSERVE &nbsp;&nbsp; 02 / INVESTIGATE &nbsp;&nbsp; 03 / RESPOND</div></section>
<main class="tp-login-form"><div class="login-form-inner"><span class="login-kicker">YOUR WORKSPACE AWAITS</span><h2>Welcome back.</h2><p>Sign in to continue your investigation.</p>
<?php if($error): ?><div class="login-error" role="alert"><?= htmlspecialchars($error,ENT_QUOTES,'UTF-8') ?></div><?php endif; ?>
<form method="post" action="login.php"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'],ENT_QUOTES,'UTF-8') ?>"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required placeholder="Your analyst username"><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required placeholder="Enter your password"><button type="submit">Enter workspace <span aria-hidden="true">↗</span></button></form><p class="login-access">Access is managed by your administrator.<br>Use your configured lab account.</p></div><footer>ThreatPulse <span>SIEM + SOAR</span></footer></main></body></html>
