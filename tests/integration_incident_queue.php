<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentRepository.php';
require_once __DIR__.'/../includes/soar/IncidentQueueQuery.php';
function queueCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$pdo->beginTransaction();
try {
    $name = 'queue-ci-'.bin2hex(random_bytes(6));
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash','analyst']);
    $user = (int)$pdo->lastInsertId();
    $repo = new IncidentRepository($pdo);
    $ids = [];
    $specs = [
        ['NEW', 'P3', null, 0, 'alpha 100%_!'],
        ['OPEN', 'P1', $user, 0, 'bravo'],
        ['INVESTIGATING', 'P2', null, 0, 'charlie'],
        ['CONTAINED', 'P2', $user, 0, 'delta'],
        ['RESOLVED', 'P1', null, 0, 'echo'],
        ['CLOSED', 'P4', $user, 0, 'foxtrot'],
        ['NEW', 'P1', null, 1, 'simulation'],
    ];
    foreach ($specs as $n=>[$status,$priority,$assigned,$simulated,$title]) {
        $id = $repo->create(['incident_number'=>$name.'-'.$n, 'title'=>$name.' '.$title, 'status'=>$status, 'priority'=>$priority, 'assigned_to'=>$assigned, 'is_simulated'=>$simulated, 'attack_category'=>$n < 2 ? 'QUEUE_A' : 'QUEUE_B']);
        $ids[] = $id;
        $pdo->prepare("UPDATE incidents SET created_at='2020-01-01 00:00:00', updated_at=DATE_SUB(NOW(), INTERVAL ? DAY) WHERE id=?")->execute([$n < 2 ? 8 : 0, $id]);
    }
    $base = ['q'=>$name];
    $expect = function(array $filters, array $expected, string $message) use ($repo,$base): void {
        $filters = array_merge($base,$filters);
        $actual = array_map('intval', array_column($repo->listIncidents($filters), 'id'));
        sort($actual); sort($expected);
        queueCheck($actual === $expected && $repo->countIncidents($filters) === count($expected), $message);
    };
    $expect([], array_slice($ids,0,6), 'real cases are the default for both count and list');
    $expect(['kind'=>'simulated'], [$ids[6]], 'simulation filter is isolated');
    $expect(['kind'=>'all'], $ids, 'all cases requires an explicit filter');
    $expect(['lifecycle'=>'active'], array_slice($ids,0,4), 'active includes contained and excludes resolved/closed');
    $expect(['lifecycle'=>'finished'], [$ids[4],$ids[5]], 'finished states are resolved and closed');
    $expect(['unassigned'=>true,'lifecycle'=>'active'], [$ids[0],$ids[2]], 'unassigned active work combines filters');
    $mine = IncidentQueueQuery::parse(['q'=>$name,'owner'=>'mine'], $user);
    $expect($mine['filters'], [$ids[1],$ids[3],$ids[5]], 'mine uses authenticated identity');
    $expect(['stale_days'=>7,'lifecycle'=>'active'], [$ids[0],$ids[1]], 'case-update age uses database time');
    $expect(['status'=>'CLOSED','lifecycle'=>'active'], [], 'conflicting filters return an honest empty result');
    $expect(['priority'=>'P1','severity'=>'MEDIUM'], [$ids[1],$ids[4]], 'priority and severity combine');
    $expect(['category'=>'QUEUE_A','created_after'=>'2019-12-31','created_before'=>'2020-01-02'], [$ids[0],$ids[1]], 'legacy category and date filters now agree with counts');
    $expect(['created_after'=>'2021-01-01'], [], 'date filter count excludes older rows');
    $expect(['q'=>$name.' alpha 100%_!'], [$ids[0]], 'percent, underscore and escape characters search literally');
    $expect(['q'=>"' OR 1=1 -- ".$name], [], 'SQL-like input is bound as data');
    $expect(['q'=>$name.'-4'], [$ids[4]], 'incident number search works');
    $ordered = fn(array $extra): array => array_map('intval',array_column($repo->listIncidents(array_merge($base,$extra)), 'id'));
    queueCheck($ordered(['sort'=>'newest']) === array_reverse(array_slice($ids,0,6)), 'newest ties use descending ID');
    queueCheck($ordered(['sort'=>'oldest']) === array_slice($ids,0,6), 'oldest ties use ascending ID');
    queueCheck($ordered(['sort'=>'least_updated']) === array_slice($ids,0,6), 'least updated ties use ascending ID');
    queueCheck($ordered(['sort'=>'priority']) === [$ids[4],$ids[1],$ids[3],$ids[2],$ids[0],$ids[5]], 'priority ordering has deterministic tie breaks');
    queueCheck($ordered(['sort'=>'id; DROP TABLE incidents']) === $ordered(['sort'=>'priority']), 'unknown sort never becomes SQL');
    $first = $repo->listIncidents($base+['sort'=>'oldest'],2,0);
    $second = $repo->listIncidents($base+['sort'=>'oldest'],2,2);
    queueCheck(array_map('intval',array_column(array_merge($first,$second),'id')) === array_slice($ids,0,4), 'adjacent pages have no duplicate or missing tied rows');
    $old = IncidentQueueQuery::parse(['mine'=>'1'], $user);
    queueCheck($old['filters']['assigned_to'] === $user, 'original mine bookmarks remain valid');
    foreach ([['q'=>[]], ['q'=>str_repeat('x',201)], ['owner'=>'mine']] as $input) {
        $bad=false; try { IncidentQueueQuery::parse($input,null); } catch (InvalidArgumentException $e) { $bad=true; }
        queueCheck($bad,'invalid search or identity-free mine request is rejected');
    }
    $safe = IncidentQueueQuery::parse(['kind'=>[], 'page'=>[], 'sort'=>'DROP', 'stale_days'=>'-1'],null);
    queueCheck($safe['query']['kind']==='observed' && $safe['page']===1 && $safe['query']['sort']==='priority' && $safe['query']['stale_days']==='', 'malformed optional inputs use safe defaults');
    $pdo->rollBack();
    echo "Incident queue integration passed; fixtures rolled back.\n";
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n"); exit(1);
}
