<?php
/** CLI-only bootstrapping of an isolated, disposable public-demo database. */
if (PHP_SAPI !== 'cli' || getenv('APP_ENV') !== 'public-demo') {
    http_response_code(404); exit(1);
}
$adminPassword = getenv('PUBLIC_DEMO_ADMIN_PASSWORD');
$dbPassword = getenv('DB_PASS');
if (!is_string($adminPassword) || strlen($adminPassword) < 20 ||
    !is_string($dbPassword) || strlen($dbPassword) < 32) {
    fwrite(STDERR, "Set private generated PUBLIC_DEMO_ADMIN_PASSWORD (20+ characters) and DB_PASS (32+ characters).\n");
    exit(1);
}
if (($argv[1] ?? '') === '--preflight') exit(0);
try {
    $root = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=threatpulse_public_demo;charset=utf8mb4', 'root', '', [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $quoted = $root->quote($dbPassword);
    $root->exec("CREATE USER IF NOT EXISTS 'demo_app'@'localhost' IDENTIFIED BY $quoted");
    $root->exec("ALTER USER 'demo_app'@'localhost' IDENTIFIED BY $quoted");
    $root->exec("GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON threatpulse_public_demo.* TO 'demo_app'@'localhost'");
    // Replace every shipped account password before Apache is allowed to listen.
    $stmt=$root->prepare('UPDATE users SET password=?, failed_attempts=0, locked_until=NULL WHERE id=?');
    foreach ($root->query('SELECT id, username FROM users')->fetchAll(PDO::FETCH_ASSOC) as $user) {
        $password=$user['username']==='admin' ? $adminPassword : bin2hex(random_bytes(32));
        $stmt->execute([password_hash($password, PASSWORD_ARGON2ID), $user['id']]);
    }
    echo "Public demo credentials initialized; passwords are never written to logs.\n";
} catch (Throwable $e) {
    fwrite(STDERR, "Public demo account setup failed; refusing to start HTTP service.\n");
    exit(1);
}
