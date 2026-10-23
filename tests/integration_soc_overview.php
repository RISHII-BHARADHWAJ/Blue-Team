<?php
declare(strict_types=1);
if (PHP_SAPI!=='cli' || getenv('SOAR_INTEGRATION_TEST')!=='1' || getenv('DB_HOST')!=='db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soc/SocOverviewService.php';
require_once __DIR__.'/../includes/siem/EventEvidenceRepository.php';
require_once __DIR__.'/../includes/soar/IncidentRepository.php';
function overviewCheck(bool $ok,string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$service=new SocOverviewService($pdo);
$standalone=$service->build();
overviewCheck(!$pdo->inTransaction() && !$standalone['errors'], 'standalone overview releases its read transaction');
$pdo->beginTransaction();
try {
    $before=$service->build();
    $name='overview-'.bin2hex(random_bytes(5));
    $ip='2001:db8:'.bin2hex(random_bytes(2)).':'.bin2hex(random_bytes(2)).'::1';
    $clock=$pdo->query("SELECT UTC_TIMESTAMP() AS current_time_utc, DATE_SUB(UTC_TIMESTAMP(),INTERVAL 3 DAY) AS old_time,
        DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 DAY) AS future_time")->fetch();
    $repo=new EventEvidenceRepository($pdo);
    $append=function(bool $simulation,string $receipt,string $event,string $message) use ($pdo,$repo,$name,$ip): int {
        $pdo->prepare("INSERT INTO logs (source_ip,severity,category,message,timestamp) VALUES (?,'CRITICAL','Other',?,?)")->execute([$ip,$message,$event]);
        $id=(int)$pdo->lastInsertId();
        $repo->append($id,['source'=>$name,'source_type'=>'sensor','source_event_id'=>(string)$id,'is_simulated'=>$simulation,
            'event_timestamp'=>$event,'received_at'=>$receipt],['timestamp'=>$event,'message'=>$message],hash('sha256',$name.$id),'ci-overview',null);
        return $id;
    };
    // Same receipt timestamps exercise stable ID ordering. Source time is intentionally old.
    $logs=[];
    for($i=0;$i<16;$i++) $logs[]=$append(false,$clock['current_time_utc'],$clock['old_time'],$name.' event '.$i);
    $append(false,$clock['old_time'],$clock['current_time_utc'],$name.' old receipt');
    $future=$append(false,$clock['future_time'],$clock['future_time'],str_repeat('x',510));
    $append(true,$clock['future_time'],$clock['future_time'],'SIMULATION_MUST_NOT_APPEAR');
    $pdo->prepare("INSERT INTO logs (source_ip,severity,message) VALUES (?,'CRITICAL','LEGACY_MUST_NOT_APPEAR')")->execute([$ip]);
    foreach(['a','b'] as $suffix) $pdo->prepare("INSERT INTO threat_feed_indicators (provider,indicator_type,indicator_value) VALUES (?,'IPV6',?)")->execute([$name.$suffix,$ip]);
    $cases=new IncidentRepository($pdo);$caseIds=[];
    foreach(['NEW','OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED'] as $n=>$status) {
        $id=$cases->create(['incident_number'=>$name.'-'.$n,'title'=>$name,'status'=>$status,'priority'=>'P1']);$caseIds[]=$id;
        $pdo->prepare("UPDATE incidents SET created_at='2000-01-01',updated_at=DATE_SUB(NOW(),INTERVAL 8 DAY) WHERE id=?")->execute([$id]);
    }
    $cases->create(['incident_number'=>$name.'-sim','title'=>'SIMULATION_CASE','is_simulated'=>true,'priority'=>'P1']);
    $view=$service->build();
    overviewCheck($pdo->inTransaction(), 'caller transaction remains open');
    overviewCheck($view['evidence']['total']===$before['evidence']['total']+18, 'evidence totals exclude legacy logs, simulation and feed listings');
    overviewCheck($view['evidence']['received_24h']===$before['evidence']['received_24h']+16, '24-hour metric uses receipt time and excludes old and future receipts');
    overviewCheck($view['evidence']['source_ips']===$before['evidence']['source_ips']+1, 'source IP count is distinct and evidence-scoped');
    $rows=$view['evidence']['recent'];
    overviewCheck(count($rows)===12 && (int)$rows[0]['log_id']===$future && (int)$rows[1]['log_id']===$logs[15], 'recent evidence is bounded and receipt ties use descending IDs');
    overviewCheck(strlen($rows[0]['message'])===500 && (int)$rows[0]['message_truncated']===1, 'long message truncation is explicit');
    overviewCheck(!str_contains(json_encode($rows),'MUST_NOT_APPEAR'), 'legacy and simulated messages never enter recent sensor evidence');
    overviewCheck(array_sum(array_column($view['evidence']['severities'],'n'))===$view['evidence']['total'], 'severity buckets describe the same evidence population');
    overviewCheck($view['incidents']['active']===$before['incidents']['active']+4 && $view['incidents']['unassigned']===$before['incidents']['unassigned']+4,
        'active real workload includes contained but excludes finished and simulated cases');
    overviewCheck($view['incidents']['p1']===$before['incidents']['p1']+4 && $view['incidents']['unchanged_7d']===$before['incidents']['unchanged_7d']+4, 'P1 and unchanged metrics cover active real cases only');
    overviewCheck(count($view['incidents']['rows'])<=6 && (int)$view['incidents']['rows'][0]['id']===$caseIds[0], 'case preview prioritizes P1 then oldest created with ID tie break');
    overviewCheck($view['intelligence']['listings']===$before['intelligence']['listings']+2 && $view['intelligence']['providers']===$before['intelligence']['providers']+2,
        'same indicator from two providers is explicitly two listings');
    $digest=fn():string=>hash('sha256',json_encode($pdo->query("SELECT id,status,updated_at FROM incidents WHERE title=".$pdo->quote($name)." ORDER BY id")->fetchAll()));
    $unchanged=$digest();$again=$service->build();
    overviewCheck($digest()===$unchanged && $again['incidents']===$view['incidents'], 'overview reads do not alter incident state or update age');
    // Connection-local shadows simulate missing migration columns without changing real tables.
    $pdo->exec('CREATE TEMPORARY TABLE event_evidence (unrelated INT)');
    $partial=$service->build();
    overviewCheck($partial['evidence']===null && $partial['errors']===['evidence'] && $partial['incidents']!==null && $partial['intelligence']!==null,
        'unavailable evidence is null while independent sections remain usable');
    $pdo->exec('DROP TEMPORARY TABLE event_evidence');
    // MariaDB rejects CREATE TEMPORARY TABLE x LIKE x; define only the read projection.
    $pdo->exec('CREATE TEMPORARY TABLE event_evidence (id BIGINT,log_id INT,is_simulated TINYINT,received_at DATETIME,event_timestamp DATETIME,source VARCHAR(100),source_type VARCHAR(50))');
    $pdo->exec('CREATE TEMPORARY TABLE incidents (id BIGINT,incident_number VARCHAR(32),title VARCHAR(255),severity VARCHAR(20),status VARCHAR(20),priority VARCHAR(2),assigned_to INT,is_simulated TINYINT,created_at DATETIME,updated_at DATETIME)');
    $pdo->exec('CREATE TEMPORARY TABLE threat_feed_indicators (provider VARCHAR(64),fetched_at DATETIME)');
    $empty=$service->build();
    overviewCheck(!$empty['errors'] && $empty['evidence']['total']===0 && $empty['evidence']['received_24h']===0 && $empty['evidence']['recent']===[] && $empty['incidents']['active']===0 && $empty['intelligence']['listings']===0,
        'successful empty sections are real zero results');
    foreach(['event_evidence','incidents','threat_feed_indicators'] as $table) $pdo->exec("DROP TEMPORARY TABLE $table");
    $pdo->rollBack();
    echo "SOC overview integration passed; fixtures rolled back.\n";
} catch(Throwable $e) {
    foreach(['event_evidence','incidents','threat_feed_indicators'] as $table) $pdo->exec("DROP TEMPORARY TABLE IF EXISTS $table");
    if($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n");exit(1);
}
