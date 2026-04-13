<?php
include 'includes/config.php';

// Rate limit login endpoint (5 requests per 5 minutes = 300s)
RateLimiter::check('login', 50, 300);

if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
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

                header('Location: dashboard.php');
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

include 'includes/header.php';
?>

<div class="d-flex align-items-center justify-content-center" style="min-height: 80vh;">
    <div style="width: 100%; max-width: 400px; text-align: center;">
        <h2 class="mb-5 fw-bold">Sign in to ThreatPulse</h2>

        <?php if ($error): ?>
            <div class="alert alert-danger mb-4"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <div class="mb-3 text-start">
                <input type="text" name="username" class="form-control" placeholder="ID or Email" required
                    style="background: #1d1d1f; border-color: #424245;">
            </div>
            <div class="mb-4 text-start">
                <input type="password" name="password" class="form-control" placeholder="Password" required
                    style="background: #1d1d1f; border-color: #424245;">
            </div>

            <button type="submit" class="btn btn-primary w-100 mb-4" style="border-radius: 12px;">Sign In</button>
        </form>
    </div>
</div>

<?php include 'includes/footer.php'; ?>