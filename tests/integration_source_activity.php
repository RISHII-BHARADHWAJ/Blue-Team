<?php
declare(strict_types=1);
require_once __DIR__.'/source_activity_fixtures.php';
function sourceCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$service = new SourceActivityService($pdo);
$pdo->beginTransaction();
try {
    $name = 'source-ci-'.bin2hex(random_bytes(5));
    $fresh = sourceFixture($pdo,$name.'-fresh','actor A',-60);
    sourceFixture($pdo,$name.'-fresh','actor A',-7200);
    sourceFixture($pdo,$name.'-fresh','actor B',-60);
    sourceFixture($pdo,$name.'-fresh','actor a',-60);
    sourceFixture($pdo,$name.'-FRESH','actor A',-60);
    sourceFixture($pdo,$name.'-quiet','actor A',-2*86400);
    sourceFixture($pdo,$name.'-future','actor A',86400);
    sourceFixture($pdo,$name.'-mixed','actor A',-2*86400);
    sourceFixture($pdo,$name.'-mixed','actor A',86400);
    sourceFixture($pdo,$name.'-fresh','actor A',-60,true);
    sourceFixture($pdo,$name.'-100%_!','actor A',-60);
    sourceFixture($pdo,$name.'-100XYZ','actor A',-60);
    $unicodeSource = str_repeat('界',80);
    $longActor = $name.str_repeat('人',210);
    $longId = sourceFixture($pdo,$unicodeSource,$longActor,-60);
    sourceFixture($pdo,$unicodeSource,$longActor.'X',-60);
    $pdo->prepare("INSERT INTO logs (source_ip,severity,message) VALUES ('192.0.2.90','INFO',?)")->execute([$name.'-legacy']);
    $pdo->prepare("INSERT INTO threat_feed_indicators (provider,indicator_type,indicator_value) VALUES (?,'IPV4','192.0.2.90')")->execute([$name]);
    $data = $service->search(['q'=>$name]);
    sourceCheck($data['total'] === 11, 'identities exclude simulation, legacy and feeds; case-distinct names and submitters remain separate');
    $byKey = [];
    foreach ($data['rows'] as $row) $byKey[$row['source'].'|'.$row['submitted_by']] = $row;
    $freshRow = $byKey[$name.'-fresh|actor A'];
    sourceCheck($freshRow['stored_count'] === 2 && $freshRow['recent_count'] === 2 && $freshRow['activity'] === 'recent', 'recent activity counts receipt times rather than old source event times');
    sourceCheck($byKey[$name.'-quiet|actor A']['activity'] === 'quiet', 'old receipts are quiet in a 24-hour window');
    $future = $byKey[$name.'-future|actor A'];
    sourceCheck($future['recent_count'] === 0 && $future['last_received_at'] === null && $future['first_received_at'] === null && $future['future_count'] === 1 && $future['activity'] === 'clock', 'future-only receipts are flagged and cannot look recently active');
    $mixed = $byKey[$name.'-mixed|actor A'];
    sourceCheck($mixed['recent_count'] === 0 && $mixed['future_count'] === 1 && $mixed['last_received_at'] !== null && $mixed['stored_count'] === 2, 'future receipts do not replace the last valid receipt');
    sourceCheck($service->search(['q'=>$name,'activity'=>'clock'])['total'] === 2, 'clock filter returns future receipt groups');
    sourceCheck($service->search(['q'=>$name,'activity'=>'quiet'])['total'] === 1, 'quiet filter excludes separately flagged clock groups');
    sourceCheck($service->search(['q'=>$name,'hours'=>'168','activity'=>'quiet'])['total'] === 0, 'longer windows recognize older receipts');
    $hour = $service->search(['q'=>$name.'-fresh','hours'=>'1']);
    foreach ($hour['rows'] as $row) sourceCheck($row['recent_count'] === 1, 'hour window excludes two-hour-old receipts');
    sourceCheck($service->search(['q'=>$name.'-100%_!'])['total'] === 1, 'search treats percent underscore and escape characters literally');
    sourceCheck($service->search(['q'=>"' OR 1=1 -- ".$name])['total'] === 0, 'SQL-like search text remains data');
    $simulation = $service->search(['q'=>$name,'kind'=>'simulated']);
    sourceCheck($simulation['total'] === 1 && $simulation['rows'][0]['stored_count'] === 1, 'simulated view is separate from real receipts');
    $events = new EventEvidenceRepository($pdo);
    $drill = $events->search(['source'=>$name.'-fresh','submitted_by'=>'actor A','kind'=>'observed']);
    sourceCheck($drill['total'] === 2 && (int)$drill['rows'][0]['log_id'] === $fresh, 'drill-down isolates exact case-sensitive source and submitter pair');
    $long = $events->search(['source'=>$unicodeSource,'submitted_by'=>$longActor,'kind'=>'observed']);
    sourceCheck($long['total'] === 1 && (int)$long['rows'][0]['log_id'] === $longId, 'full-width Unicode source and submitter filters are not truncated');
    // Tied receipts exercise deterministic adjacent pages using binary identity keys.
    for ($n=0;$n<27;$n++) sourceFixture($pdo,$name.'-pages',sprintf('page-%02d',$n),-600);
    $pdo->prepare("UPDATE event_evidence SET received_at='2020-01-01 00:00:00' WHERE source=?")->execute([$name.'-pages']);
    foreach (['newest','oldest','volume'] as $sort) {
        $one = $service->search(['q'=>$name.'-pages','sort'=>$sort]);
        $two = $service->search(['q'=>$name.'-pages','sort'=>$sort],PHP_INT_MAX);
        $actors = array_column(array_merge($one['rows'],$two['rows']),'submitted_by');
        sourceCheck(count($one['rows']) === 25 && $two['page'] === 2 && $actors === array_map(fn($n)=>sprintf('page-%02d',$n),range(0,26)), 'all sorts resolve ties consistently across clamped pages');
    }
    $volume = $service->search(['q'=>$name,'sort'=>'volume']);
    sourceCheck($volume['rows'][0]['source'] === $name.'-fresh' && $volume['rows'][0]['submitted_by'] === 'actor A', 'volume sort prioritizes receipts within selected window');
    $empty = $service->search(['q'=>$name.'-missing'],9999);
    sourceCheck($empty['total'] === 0 && $empty['rows'] === [] && $empty['page'] === 1, 'empty result is a valid zero with page one');
    foreach ([['q'=>[]],['q'=>str_repeat('x',201)],['q'=>"\xFF"],['kind'=>'all'],['hours'=>'0'],['sort'=>'DROP'],['activity'=>'healthy']] as $input) {
        $bad = false; try { $service->search($input); } catch (InvalidArgumentException $e) { $bad = true; }
        sourceCheck($bad,'invalid filters are rejected');
    }
    foreach ([['submitted_by'=>[]],['submitted_by'=>str_repeat('x',1021)],['source'=>"\xFF"]] as $input) {
        $bad = false; try { $events->search($input); } catch (InvalidArgumentException $e) { $bad = true; }
        sourceCheck($bad,'malformed exact identity filters are rejected');
    }
    sourceCheck($pdo->inTransaction(), 'read service leaves borrowed transaction open');
    $pdo->rollBack();
    sourceCheck($service->search(['q'=>$name])['total'] === 0 && !$pdo->inTransaction(), 'owned snapshot closes and fixtures rolled back');
    $pdo->exec('CREATE TEMPORARY TABLE event_evidence (unrelated INT)');
    $failed = false; try { $service->search(); } catch (PDOException $e) { $failed = true; }
    sourceCheck($failed && !$pdo->inTransaction(), 'missing schema raises unavailable rather than returning false zero and rolls back owned transaction');
    $pdo->beginTransaction();
    $failed = false; try { $service->search(); } catch (PDOException $e) { $failed = true; }
    sourceCheck($failed && $pdo->inTransaction(), 'failed borrowed reads leave caller transaction under caller control');
    $pdo->rollBack();
    $pdo->exec('DROP TEMPORARY TABLE event_evidence');
    echo "Source activity integration passed.\n";
} catch (Throwable $e) {
    $pdo->exec('DROP TEMPORARY TABLE IF EXISTS event_evidence');
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n"); exit(1);
}
