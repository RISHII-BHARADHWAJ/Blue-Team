<?php
declare(strict_types=1);
require_once __DIR__.'/event_escalation_fixtures.php';
require_once __DIR__.'/../includes/soar/IncidentLinkedEvidenceWorkspace.php';
function linkedCheck(bool $ok,string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$manager = new IncidentManager($pdo); $repo = new IncidentRepository($pdo); $workspace = new IncidentLinkedEvidenceWorkspace($pdo);
$pdo->beginTransaction();
try {
    $name = 'linked-ci-'.bin2hex(random_bytes(5));
    $id = $repo->create(['incident_number'=>$name,'title'=>$name]);
    $other = $repo->create(['incident_number'=>$name.'-other','title'=>$name]);
    $sim = $repo->create(['incident_number'=>$name.'-sim','title'=>$name,'is_simulated'=>true]);
    $logs = [];
    for ($n=0;$n<27;$n++) {
        $message = $n === 26 ? str_repeat('界',510).'TAIL_SENTINEL' : $name.'-'.$n;
        $logs[] = escalationFixture($pdo,$message);
        $repo->attachAlert($id,$logs[$n],'TEST_RULE');
    }
    $legacy = escalationFixture($pdo,'LEGACY_ONLY',false,true); $repo->attachAlert($id,$legacy,'LEGACY_RULE');
    $repo->attachAlert($other,$logs[0],'SHARED_RULE');
    $unrelated = escalationFixture($pdo,'OTHER_CASE_ONLY'); $repo->attachAlert($other,$unrelated,'OTHER_RULE');
    $simLog = escalationFixture($pdo,'SIM_ONLY',true); $repo->attachAlert($sim,$simLog,'TRAINING_RULE');
    $pdo->prepare("UPDATE logs l JOIN incident_alerts ia ON ia.log_id=l.id SET l.timestamp='2020-01-01 00:00:00' WHERE ia.incident_id=?")->execute([$id]);
    $pdo->prepare("UPDATE event_evidence e JOIN incident_alerts ia ON ia.log_id=e.log_id SET e.event_timestamp='2020-01-01 00:00:00' WHERE ia.incident_id=?")->execute([$id]);
    $pdo->prepare("UPDATE incident_alerts SET added_at='2020-02-01 00:00:00' WHERE incident_id=?")->execute([$id]);
    $pdo->prepare('UPDATE logs SET message=? WHERE id=?')->execute(['literal 100%_! needle',$logs[0]]);
    $pdo->prepare('UPDATE event_evidence SET source_event_id=? WHERE log_id=?')->execute(['SOURCE_EVENT_SENTINEL',$logs[1]]);
    $all = array_merge($logs,[$legacy]);
    $first = $workspace->view($id,['sort'=>'event_oldest']); $last = $workspace->view($id,['sort'=>'event_oldest'],PHP_INT_MAX);
    linkedCheck($first['total'] === 28 && count($first['rows']) === 25 && $last['page'] === 2 && array_map('intval',array_column(array_merge($first['rows'],$last['rows']),'log_id')) === $all, 'case-scoped pages include all links exactly once with stable timestamp ties');
    foreach (['event_newest','attached_newest'] as $sort) {
        $rows = $workspace->view($id,['sort'=>$sort])['rows'];
        linkedCheck(array_map('intval',array_column($rows,'log_id')) === array_slice(array_reverse($all),0,25), 'newest event and attachment order use stable link ID ties');
    }
    $pdo->prepare("UPDATE incident_alerts SET added_at='2021-01-01 00:00:00' WHERE incident_id=? AND log_id=?")->execute([$id,$logs[0]]);
    $pdo->prepare("UPDATE event_evidence SET event_timestamp='2022-01-01 00:00:00' WHERE log_id=?")->execute([$logs[1]]);
    linkedCheck((int)$workspace->view($id,['sort'=>'attached_newest'])['rows'][0]['log_id'] === $logs[0], 'attachment sort uses link time before ID');
    linkedCheck((int)$workspace->view($id)['rows'][0]['log_id'] === $logs[1], 'event sort uses preserved event time before legacy log time');
    linkedCheck($workspace->view($id,['provenance'=>'preserved'])['total'] === 27, 'preserved-only filter excludes legacy records');
    $old = $workspace->view($id,['provenance'=>'legacy']);
    linkedCheck($old['total'] === 1 && $old['rows'][0]['evidence_id'] === null && $old['rows'][0]['source'] === null, 'legacy records remain visible without fabricated provenance');
    linkedCheck($workspace->view($id,['q'=>'100%_!','severity'=>'MEDIUM','source_ip'=>'192.0.2.89','provenance'=>'preserved'])['total'] === 1, 'literal text, source IP, severity alias and provenance combine');
    linkedCheck($workspace->view($id,['q'=>'SOURCE_EVENT_SENTINEL'])['total'] === 1, 'source event ID search works');
    linkedCheck($workspace->view($id,['source_ip'=>'192.0.2.200'])['total'] === 0 && $workspace->view($id,['severity'=>'HIGH'])['total'] === 0, 'exact IP and severity filters exclude nonmatches');
    foreach (['OTHER_CASE_ONLY','SIM_ONLY',"' OR 1=1 --"] as $q) linkedCheck($workspace->view($id,['q'=>$q])['total'] === 0, 'other cases, simulation and SQL-like text cannot broaden results');
    $long = $workspace->view($id,['q'=>'TAIL_SENTINEL'])['rows'][0];
    linkedCheck(strlen($long['message']) === 1500 && (int)$long['message_truncated'] === 1 && !array_key_exists('raw_payload',$long) && !array_key_exists('canonical_json',$long), 'full-text search finds content beyond a Unicode-safe 500-character preview without loading payloads');
    $training = $workspace->view($sim);
    linkedCheck((int)$training['incident']['is_simulated'] === 1 && $training['total'] === 1 && (int)$training['rows'][0]['is_simulated'] === 1, 'simulated case and evidence remain explicitly classified');
    $preview = $manager->getIncident($id,20,20);
    linkedCheck(count($preview['alerts']) === 20 && $preview['alerts_total'] === 28 && (int)$preview['alerts'][0]['log_id'] === $legacy, 'main case preview is bounded and reports complete link count');
    $previewLong = array_values(array_filter($preview['alerts'],fn($r)=>(int)$r['log_id'] === $logs[26]))[0];
    linkedCheck(strlen($previewLong['message']) === 1500 && (int)$previewLong['message_truncated'] === 1, 'main preview bounds long messages in SQL');
    $legacyApi = $manager->getIncident($id);
    $fullLong = array_values(array_filter($legacyApi['alerts'],fn($r)=>(int)$r['log_id'] === $logs[26]))[0];
    linkedCheck(count($legacyApi['alerts']) === 28 && str_contains($fullLong['message'],'TAIL_SENTINEL') && !array_key_exists('message_truncated',$fullLong) && !array_key_exists('alerts_total',$legacyApi), 'default manager and API retain complete messages and existing response shape');
    $before = $repo->find($id); $workspace->view($id);
    linkedCheck($pdo->inTransaction() && $repo->find($id) === $before, 'read leaves case fields and borrowed transaction unchanged');
    foreach ([['q'=>[]],['q'=>str_repeat('x',201)],['q'=>"\xff"],['source_ip'=>str_repeat('x',46)],['severity'=>'DROP'],['sort'=>'bad'],['provenance'=>[]]] as $input) {
        $bad = false; try { $workspace->view($id,$input); } catch (InvalidArgumentException $e) { $bad = true; }
        linkedCheck($bad,'malformed filters are rejected');
    }
    $pdo->rollBack();
    $missing = false; try { $workspace->view($id); } catch (OutOfBoundsException $e) { $missing = true; }
    linkedCheck($missing && !$pdo->inTransaction(), 'missing cases close their owned read transaction');
    $emptyId = $repo->create(['incident_number'=>$name.'-empty','title'=>$name]);
    $empty = $workspace->view($emptyId,[],999);
    linkedCheck($empty['total'] === 0 && $empty['rows'] === [] && $empty['page'] === 1 && !$pdo->inTransaction(), 'empty linked evidence returns a valid first page and closes snapshot');
    $pdo->exec('CREATE TEMPORARY TABLE event_evidence (unrelated INT)');
    $failed = false; try { $workspace->view($emptyId); } catch (PDOException $e) { $failed = true; }
    $pdo->exec('DROP TEMPORARY TABLE event_evidence');
    linkedCheck($failed && !$pdo->inTransaction(), 'missing evidence schema fails explicitly instead of misclassifying rows as legacy');
    echo "Linked evidence integration passed.\n";
} catch (Throwable $e) {
    $pdo->exec('DROP TEMPORARY TABLE IF EXISTS event_evidence');
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n"); exit(1);
}
