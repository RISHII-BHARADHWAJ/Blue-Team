<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/audit/AuditHistoryService.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
function auditUser(PDO $pdo,string $name,string $role): int {
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash',$role]);
    return (int)$pdo->lastInsertId();
}
function auditFixture(PDO $pdo,string $actor,string $action,?string $result,string $target,string $time='2020-01-02 12:00:00'): int {
    $pdo->prepare('INSERT INTO audit_log (analyst,ip_address,action,result,target,timestamp,details,user_agent) VALUES (?,?,?,?,?,?,?,?)')->execute([
        $actor,'192.0.2.91',$action,$result,$target,$time,'{"token":"DETAIL_SECRET_SENTINEL"}','AGENT_SECRET_SENTINEL']);
    return (int)$pdo->lastInsertId();
}
