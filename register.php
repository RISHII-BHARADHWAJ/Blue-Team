<?php
if (getenv('APP_ENV') !== 'public-demo') { http_response_code(404); exit; }
require __DIR__.'/includes/config.php';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!is_string($_POST['csrf_token'] ?? null) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403); exit('Invalid form token.');
    }
    RateLimiter::check('signup', 5, 900);
    $name = $_POST['username'] ?? null;
    $pass = $_POST['password'] ?? null;
    if (!is_string($name) || !preg_match('/^[A-Za-z0-9_]{3,32}$/D', $name) || !is_string($pass) || strlen($pass)<12 || strlen($pass)>128) {
        $error = 'Use a username of 3–32 letters, digits or underscores and a password of 12–128 bytes.';
    } else {
        try {
            $pdo->prepare("INSERT INTO users(username,password,role) VALUES(?,?,'demo_viewer')")
                ->execute([$name,password_hash($pass,PASSWORD_ARGON2ID)]);
            header('Location: login.php', true, 303); exit;
        } catch (PDOException $e) {
            if (($e->errorInfo[1] ?? null) !== 1062) throw $e;
            $error = 'Username unavailable. Choose another.';
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] !== 'GET') { http_response_code(405); exit; }
?>
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Create account · ThreatPulse</title><link rel="stylesheet" href="assets/css/themes.css"><link rel="stylesheet" href="assets/css/login.css">
<main class="tp-login-form"><div class="login-form-inner"><h1>Create a dashboard account</h1>
<p>View the shared demo overview. Your account may reset when the demo restarts.</p>
<?php if ($error): ?><p role="alert"><?= htmlspecialchars($error) ?></p><?php endif; ?>
<form method="post"><input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" pattern="[A-Za-z0-9_]{3,32}" required>
<label for="password">Password (at least 12 characters)</label><input id="password" type="password" name="password" autocomplete="new-password" minlength="12" maxlength="128" required>
<button>Create account</button></form><a href="login.php">Back to sign in</a></div></main></html>
