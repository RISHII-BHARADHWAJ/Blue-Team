<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/approvals/ApprovalQueueService.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
require_once __DIR__.'/../includes/soar/playbooks/PlaybookRepository.php';
function approvalQueueFixture(PDO $pdo): array {
    $name = 'queue-ci-'.bin2hex(random_bytes(5));
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash','user']); $uid = (int)$pdo->lastInsertId();
    $manager = new IncidentManager($pdo); $repo = new PlaybookRepository($pdo);
    $case = $manager->createIncident(['title'=>$name.' <script>probe()</script>']);
    $critical = $manager->createIncident(['title'=>$name.' critical']);
    $sim = $manager->createIncident(['title'=>$name.' simulation','is_simulated'=>true]);
    $pdo->prepare("UPDATE incidents SET priority='P3' WHERE id IN (?,?)")->execute([$case['id'],$sim['id']]);
    $pdo->prepare("UPDATE incidents SET priority='P1' WHERE id=?")->execute([$critical['id']]);
    $pb = $repo->createPlaybook(['playbook_name'=>$name,'display_name'=>'Queue fixture','category'=>'INVESTIGATION'],$uid);
    $runs = [];
    foreach ([$case,$critical,$sim] as $row) $runs[$row['id']] = $repo->createRun($pb,(int)$row['id'],'ANALYST',$uid,bin2hex(random_bytes(16)),['mode'=>'DRY_RUN']);
    $insert = $pdo->prepare('INSERT INTO approval_requests (playbook_run_id,incident_id,action_name,action_description,action_payload,required_tier,status,requested_at,expires_at) VALUES (?,?,?,?,?,?,?,?,DATE_ADD(NOW(), INTERVAL ? HOUR))');
    $add = function(array $case,string $action,string $status,int $hours,string $description='Review request') use ($pdo,$insert,$runs): int {
        $insert->execute([$runs[$case['id']],$case['id'],$action,$description,'{"token":"QUEUE_PAYLOAD_SECRET"}','LEAD',$status,'2020-01-01 00:00:00',$hours]);
        return (int)$pdo->lastInsertId();
    };
    $ids = [];
    for ($n=0;$n<101;$n++) $ids[] = $add($case,$n===0?'oldest_100%_!':'review','PENDING',8,$n===0?str_repeat('x',400).' hiddenneedle '.$name:'Review request');
    $criticalIds = [$add($critical,'critical_one','PENDING',1),$add($critical,'critical_two','PENDING',2)];
    $expired = $add($case,'expired','PENDING',-1);
    $approved = $add($case,'approved','APPROVED',-1);
    $simId = $add($sim,'token: QUEUE_METADATA_SECRET','PENDING',2);
    return compact('name','uid','case','critical','sim','ids','criticalIds','expired','approved','simId');
}
