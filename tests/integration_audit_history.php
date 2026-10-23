<?php
declare(strict_types=1);
require_once __DIR__.'/audit_history_fixtures.php';
function auditCheck(bool $ok,string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$service = new AuditHistoryService($pdo);
$pdo->beginTransaction();
try {
    $name = 'audit-ci-'.bin2hex(random_bytes(5));
    $admin = auditUser($pdo,$name.'-admin','admin'); $lead = auditUser($pdo,$name.'-lead','lead');
    $reader = auditUser($pdo,$name.'-reader','user'); $analyst = auditUser($pdo,$name.'-analyst','analyst');
    $auth = ['auth_method'=>'session','user_id'=>$admin,'tier'=>'TIER1'];
    $manager = new IncidentManager($pdo);
    $case = $manager->createIncident(['title'=>$name]); $caseId = (int)$case['id'];
    $sim = $manager->createIncident(['title'=>$name.' simulation','is_simulated'=>true]);
    $ids = [];
    for ($n=0;$n<27;$n++) $ids[] = auditFixture($pdo,$name,'review_event','success',$n%2 === 0 ? 'incident:'.$caseId : $case['incident_number']);
    $failure = auditFixture($pdo,$name,'review_failure','failure','incident:'.$sim['id'],'2020-01-01 00:00:00');
    $blocked = auditFixture($pdo,$name,'review_block','blocked','RAW_TARGET_SECRET_SENTINEL','2020-01-03 23:59:59');
    $unknown = auditFixture($pdo,$name,'review_unknown',null,'prefix'.$case['incident_number'],'2020-01-04 00:00:00');
    $literal = auditFixture($pdo,$name,'review_100%_!','success','incident:9223372036854775807');
    $secret = auditFixture($pdo,$name,'token: METADATA_SECRET_SENTINEL','success','incident:0');
    $base = ['q'=>$name];
    $first = $service->search($auth,$base+['action'=>'review_event','sort'=>'oldest']);
    $last = $service->search($auth,$base+['action'=>'review_event','sort'=>'oldest'],PHP_INT_MAX);
    auditCheck($first['total'] === 27 && count($first['rows']) === 25 && $last['page'] === 2 && array_map('intval',array_column(array_merge($first['rows'],$last['rows']),'id')) === $ids, 'bounded pages preserve timestamp ties with stable IDs and clamped page numbers');
    $newest = $service->search($auth,$base+['action'=>'review_event']);
    auditCheck(array_map('intval',array_column($newest['rows'],'id')) === array_slice(array_reverse($ids),0,25), 'newest order reverses tied IDs');
    foreach ($first['rows'] as $row) auditCheck((int)$row['case']['id'] === $caseId, 'both direct target forms resolve to the existing case');
    $filtered = $service->search($auth,$base+['case_id'=>(string)$caseId]);
    auditCheck($filtered['total'] === 27 && (int)$filtered['case']['id'] === $caseId, 'case filtering includes exact ID and number targets without substring matches');
    $simView = $service->search($auth,$base+['case_id'=>(string)$sim['id']]);
    auditCheck($simView['total'] === 1 && (int)$simView['rows'][0]['case']['is_simulated'] === 1, 'simulated case references are explicitly classified');
    foreach (['failure'=>$failure,'blocked'=>$blocked,'unknown'=>$unknown] as $result=>$expected) {
        $view = $service->search($auth,$base+['result'=>$result]);
        auditCheck($view['total'] === 1 && (int)$view['rows'][0]['id'] === $expected, 'outcome filters include explicit unrecorded results');
    }
    $dates = $service->search($auth,$base+['from'=>'2020-01-01','to'=>'2020-01-03']);
    auditCheck($dates['total'] === 31, 'date range includes both endpoint days and excludes the next midnight');
    auditCheck($service->search($auth,['q'=>'100%_!'])['total'] === 1, 'percent, underscore and escape characters are literal');
    auditCheck($service->search($auth,['q'=>"' OR 1=1 -- ".$name])['total'] === 0, 'SQL-like text remains data');
    $payload = $service->search($auth,$base+['action'=>'token: METADATA_SECRET_SENTINEL'])['rows'][0];
    auditCheck($payload['action'] === 'token: [REDACTED]' && !array_key_exists('target',$payload) && !array_key_exists('details',$payload) && !array_key_exists('user_agent',$payload), 'metadata secrets are redacted and raw targets, payloads and agents are excluded');
    $freeform = $service->search($auth,$base+['result'=>'blocked'])['rows'][0];
    auditCheck($freeform['case'] === null && !str_contains(json_encode($freeform),'SECRET_SENTINEL'), 'unrecognized targets are neither exposed nor linked');
    auditCheck($service->search(['auth_method'=>'session','user_id'=>$lead,'tier'=>'TIER1'],$base)['total'] === 32, 'database lead role authorizes even when session tier is stale lower');
    foreach ([['auth_method'=>'bearer','user_id'=>$admin],['auth_method'=>'session','user_id'=>null],['auth_method'=>'session','user_id'=>$reader,'tier'=>'ADMIN'],['auth_method'=>'session','user_id'=>$analyst,'tier'=>'ADMIN'],['auth_method'=>'session','user_id'=>2147483647]] as $bad) {
        $denied = false; try { $service->search($bad,$base); } catch (DomainException $e) { $denied = true; }
        auditCheck($denied,'reader, analyst, deleted, unnamed and bearer contexts cannot read audit metadata');
    }
    foreach ([['q'=>[]],['q'=>"\xff"],['q'=>str_repeat('x',201)],['action'=>str_repeat('x',101)],['result'=>'bad'],['from'=>'2020-02-30'],['from'=>"2020-01-\x0001"],['from'=>'2020-02-02','to'=>'2020-01-01'],['case_id'=>'-1'],['sort'=>'DROP']] as $input) {
        $invalid = false; try { $service->search($auth,$input); } catch (InvalidArgumentException $e) { $invalid = true; }
        auditCheck($invalid,'invalid filters are rejected');
    }
    $missing = false; try { $service->search($auth,['case_id'=>'2147483647']); } catch (OutOfBoundsException $e) { $missing = true; }
    auditCheck($missing && $pdo->inTransaction(), 'missing case fails explicitly and borrowed transaction remains open');
    $auditCount = (int)$pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
    $service->search($auth,$base);
    auditCheck((int)$pdo->query('SELECT COUNT(*) FROM audit_log')->fetchColumn() === $auditCount, 'history inspection creates no audit or action records');
    $pdo->rollBack();
    // An older caller snapshot must not retain access after a committed role downgrade.
    $currentAdmin = auditUser($pdo,$name.'-current','admin');
    $currentAuth = ['auth_method'=>'session','user_id'=>$currentAdmin,'tier'=>'ADMIN'];
    $empty = $service->search($currentAuth,$base,999);
    auditCheck($empty['total'] === 0 && $empty['page'] === 1 && !$pdo->inTransaction(), 'owned successful empty read closes its snapshot');
    $pdo->beginTransaction(); $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    $other = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4",$db_user,$db_pass,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $other->prepare("UPDATE users SET role='user' WHERE id=?")->execute([$currentAdmin]);
    $denied = false; try { $service->search($currentAuth); } catch (DomainException $e) { $denied = true; }
    auditCheck($denied && $pdo->inTransaction(), 'current authorization rejects a downgrade despite an older repeatable-read snapshot');
    $pdo->rollBack();
    $pdo->prepare("UPDATE users SET role='admin' WHERE id=?")->execute([$currentAdmin]);
    $pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');
    $failed = false; try { $service->search($currentAuth); } catch (PDOException $e) { $failed = true; }
    $pdo->exec('DROP TEMPORARY TABLE audit_log');
    auditCheck($failed && !$pdo->inTransaction(), 'missing audit storage raises unavailable and closes the owned transaction');
    echo "Audit history integration passed.\n";
} catch (Throwable $e) {
    $pdo->exec('DROP TEMPORARY TABLE IF EXISTS audit_log');
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n"); exit(1);
}
