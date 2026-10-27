<?php
// Runs in a disposable Compose database, never on the user's project database.
if (getenv('SOAR_INTEGRATION_TEST') !== '1') exit(1);
require __DIR__.'/../includes/db.php';
require __DIR__.'/../includes/security.php';
require __DIR__.'/../includes/auth_check.php';
require __DIR__.'/../includes/soar/SoarAuth.php';
require __DIR__.'/../includes/soar/enrichment/HttpClient.php';
function checkSecurity(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
// Don't emit output until session rotation tests finish.
$blocked = ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254',
    '100.64.0.1','100.100.100.200','100.127.255.254','224.0.0.1','0.0.0.0',
    '::1','::','::ffff:127.0.0.1','fe90::1','fd12::1','fc12::1','ff02::1','2002:7f00:1::'];
foreach ($blocked as $ip) {
    try { HttpClient::assertPublicIp($ip); throw new RuntimeException('Accepted '.$ip); }
    catch (HttpClientSecurityException $expected) {}
}
foreach (['8.8.8.8','1.1.1.1','2606:4700:4700::1111'] as $ip) HttpClient::assertPublicIp($ip);
$client = new HttpClient();
foreach (['file:///etc/passwd','http://[::ffff:127.0.0.1]/','http://127.0.0.1/',
    'http://user:password@8.8.8.8/','http://169.254.169.254/latest/meta-data/'] as $url) {
    try { $client->validateUrlSsrf($url); throw new RuntimeException('Accepted unsafe URL'); }
    catch (HttpClientSecurityException $expected) {}
}
$_SESSION['csrf_token'] = 'known-token';
checkSecurity(!verifyCSRFToken(['known-token']), 'Array CSRF accepted');
checkSecurity(!verifyCSRFToken('wrong'), 'Wrong CSRF accepted');
checkSecurity(verifyCSRFToken('known-token'), 'Valid CSRF rejected');
foreach (['last_activity'=>1801,'authenticated_at'=>28801] as $field=>$age) {
    $_SESSION = ['analyst'=>'expired','user_id'=>1,'last_activity'=>time(),'authenticated_at'=>time()];
    $_SESSION[$field] = time()-$age;
    tpStartSession();
    checkSecurity(empty($_SESSION['user_id']), 'Expired session survives '.$field);
}
$pdo->beginTransaction();
try {
    $username = 'security_'.bin2hex(random_bytes(6));
    $stmt=$pdo->prepare("INSERT INTO users(username,password,role) VALUES (?,?,'user')");
    $stmt->execute([$username,password_hash(bin2hex(random_bytes(24)),PASSWORD_DEFAULT)]);
    $id=(int)$pdo->lastInsertId();
    $_SESSION=['user_id'=>$id,'analyst'=>$username,'role'=>'admin'];
    checkSecurity(SoarAuth::getContext($pdo)['tier'] === 'TIER1', 'Stale admin role survives');
    $pdo->prepare('DELETE FROM users WHERE id=?')->execute([$id]);
    checkSecurity(SoarAuth::getContext($pdo)['auth_method'] === 'anonymous', 'Deleted user retains access');
    $_SERVER['REMOTE_ADDR']='192.0.2.253';
    $pdo->prepare('DELETE FROM rate_limits WHERE ip_action_key LIKE ?')->execute(['192.0.2.253_%']);
    $pdo->prepare("INSERT INTO rate_limits VALUES (?,49,DATE_SUB(NOW(),INTERVAL 90 SECOND))")->execute(['192.0.2.253_login']);
    RateLimiter::check('approvals_list',120,60);
    $count=$pdo->query("SELECT request_count FROM rate_limits WHERE ip_action_key='192.0.2.253_login'")->fetchColumn();
    checkSecurity((int)$count === 49, 'Short window erased login rate limit');
    RateLimiter::check('login',50,300);
    checkSecurity((int)$pdo->query("SELECT request_count FROM rate_limits WHERE ip_action_key='192.0.2.253_login'")->fetchColumn() === 50, 'Increment failed');
} finally { $pdo->rollBack(); }
echo "PASS: SSRF ranges/URLs, malformed CSRF, idle/absolute expiry, revoked roles/users, isolated rate-limit windows\n";
