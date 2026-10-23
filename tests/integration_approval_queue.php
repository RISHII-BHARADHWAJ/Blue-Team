<?php
declare(strict_types=1);
require_once __DIR__.'/approval_queue_fixtures.php';
function queueCheck(bool $ok,string $msg): void { if (!$ok) throw new RuntimeException('FAIL: '.$msg); echo "PASS: $msg\n"; }
$service = new ApprovalQueueService($pdo);
$auth = ['actor'=>'queue-reader','tier'=>'TIER1','auth_method'=>'session'];
$pdo->beginTransaction();
try {
    $f = approvalQueueFixture($pdo); $base = ['q'=>$f['name']];
    $before = $pdo->query('SELECT id,status,decided_at FROM approval_requests ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    $first = $service->search($auth,$base);
    queueCheck($first['pagination']['total']===103 && count($first['data'])===25 && $first['pagination']['pages']===5,'full queue totals exceed old 100-request ceiling');
    queueCheck($first['metrics']===['pending'=>103,'critical'=>2,'expiring'=>2],'metrics span every matching page');
    $all = [];
    for ($page=1;$page<=5;$page++) $all = array_merge($all,array_column($service->search($auth,$base+['sort'=>'oldest','page'=>$page])['data'],'id'));
    queueCheck($all===array_merge($f['ids'],$f['criticalIds']),'stable tied ordering paginates every request exactly once');
    $last = $service->search($auth,$base+['page'=>PHP_INT_MAX]);
    queueCheck($last['pagination']['page']===5 && count($last['data'])===3,'large page clamps to final nonempty page');
    $search = $service->search($auth,['q'=>'hiddenneedle '.$f['name']]);
    queueCheck(count($search['data'])===1 && $search['data'][0]['id']===$f['ids'][0] && $search['data'][0]['description_truncated']===1 && strlen($search['data'][0]['action_description'])===300,'search reaches old requests and full descriptions while previews remain bounded');
    queueCheck($service->search($auth,['q'=>'100%_!'])['pagination']['total']===1,'LIKE wildcards and escape characters are literal');
    queueCheck($service->search($auth,['q'=>"' OR 1=1 -- ".$f['name']])['pagination']['total']===0,'SQL-like search remains data');
    $expired = $service->search($auth,$base+['status'=>'EXPIRED']);
    queueCheck($expired['pagination']['total']===1 && $expired['data'][0]['id']===$f['expired'] && $expired['data'][0]['stored_status']==='PENDING','expired pending rows are derived without changing stored status');
    queueCheck($service->search($auth,$base+['status'=>'APPROVED'])['data'][0]['id']===$f['approved'],'expired timestamps do not overwrite completed decisions');
    queueCheck($service->search($auth,$base+['status'=>'','kind'=>'all'])['pagination']['total']===106,'all status/provenance view includes every fixture');
    $sim = $service->search($auth,$base+['kind'=>'simulated']);
    queueCheck($sim['pagination']['total']===1 && $sim['data'][0]['is_simulated']===1 && $sim['data'][0]['action_name']==='token: [REDACTED]','simulation isolation and metadata redaction');
    queueCheck(!str_contains(json_encode($sim),'QUEUE_PAYLOAD_SECRET') && !array_key_exists('action_payload',$sim['data'][0]),'queue never returns raw action payloads');
    $priority = $service->search($auth,$base+['sort'=>'priority']);
    queueCheck(array_slice(array_column($priority['data'],'id'),0,2)===$f['criticalIds'],'priority ordering applies before pagination');
    $expiry = $service->search($auth,$base+['sort'=>'expiry']);
    queueCheck($expiry['data'][0]['id']===$f['criticalIds'][0],'expiry ordering uses stored deadline');
    queueCheck($service->search($auth,$base+['priority'=>'P1'])['metrics']['pending']===2,'priority filter scopes counts');
    foreach ([['q'=>[]],['q'=>"\xff"],['q'=>str_repeat('a',201)],['page'=>0],['page'=>[]],['page'=>'1.5'],['status'=>'bad'],['kind'=>'bad'],['sort'=>'DROP'],['priority'=>'P9']] as $bad) {
        $rejected=false;try{$service->search($auth,$bad);}catch(InvalidArgumentException $e){$rejected=true;}queueCheck($rejected,'malformed filters rejected');
    }
    foreach ([[],['actor'=>'anonymous','tier'=>'ADMIN'],['actor'=>'user','tier'=>'GUEST']] as $bad) {
        $rejected=false;try{$service->search($bad);}catch(DomainException $e){$rejected=true;}queueCheck($rejected,'unauthorized callers rejected');
    }
    queueCheck($pdo->inTransaction() && $before===$pdo->query('SELECT id,status,decided_at FROM approval_requests ORDER BY id')->fetchAll(PDO::FETCH_ASSOC),'queue reads preserve caller transaction and approval state');
    $pdo->rollBack();
    $empty=$service->search($auth,$base);queueCheck($empty['pagination']['total']===0 && $empty['pagination']['page']===1 && !$pdo->inTransaction(),'empty owned snapshot closes cleanly');
    $pdo->exec('CREATE TEMPORARY TABLE approval_requests (unrelated INT)');
    $failed=false;try{$service->search($auth);}catch(PDOException $e){$failed=true;}
    $pdo->exec('DROP TEMPORARY TABLE approval_requests');
    queueCheck($failed && !$pdo->inTransaction(),'storage failure propagates and closes owned transaction');
    echo "Approval queue integration passed.\n";
} catch (Throwable $e) {
    $pdo->exec('DROP TEMPORARY TABLE IF EXISTS approval_requests');
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n");exit(1);
}
