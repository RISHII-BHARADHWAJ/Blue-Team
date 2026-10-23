<?php
declare(strict_types=1);
if (PHP_SAPI!=='cli' || getenv('SOAR_INTEGRATION_TEST')!=='1' || getenv('DB_HOST')!=='db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/EventEscalationService.php';
require_once __DIR__.'/../includes/siem/EventEvidenceRepository.php';
function escalationFixture(PDO $pdo,string $name,bool $simulation=false,bool $legacy=false): int {
    $alert=new AlertSchema(message:$name.' <script>eventProbe()</script>',severity:'MEDIUM',source:'escalation-test',source_type:'sensor',is_simulated:$simulation);
    $pdo->prepare("INSERT INTO logs (source_ip,severity,category,message) VALUES ('192.0.2.89','WARNING','Other',?)")->execute([$alert->message]);
    $id=(int)$pdo->lastInsertId();
    if (!$legacy) (new EventEvidenceRepository($pdo))->append($id,$alert->toArray(),['message'=>$alert->message],hash('sha256',$name.$id),'fixture-sensor',null);
    return $id;
}
function escalationUser(PDO $pdo,string $name,string $role='analyst'): int {
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash',$role]);
    return (int)$pdo->lastInsertId();
}
