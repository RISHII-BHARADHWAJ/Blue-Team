<?php
/** Concurrent simulated ingestion in disposable CI; no real incidents or response. */
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/soar/SiemSoarAlertPipeline.php';
if (($argv[1] ?? '') === 'worker') {
    try {
        $r = (new SiemSoarAlertPipeline($pdo))->ingest(['source'=>$argv[2], 'source_event_id'=>$argv[3],
            'source_ip'=>'192.0.2.73', 'severity'=>'LOW', 'message'=>'Concurrent auth test', 'is_simulated'=>true,
            'metadata'=>['event_type'=>'authentication', 'outcome'=>'failure']], 'ci-concurrent');
        if (!$r['success'] || !empty($r['duplicate'])) exit(1);
        exit(0);
    } catch (Throwable $e) { fwrite(STDERR, $e->getMessage()); exit(1); }
}
$source = 'concurrent-ci-' . bin2hex(random_bytes(6)); $workers = [];
try {
    // Hold the rule locks until all workers have launched, then release together.
    $pdo->beginTransaction(); (new DetectionEngine($pdo))->lockRules();
    for ($i=0; $i<6; $i++) {
        $process = proc_open([PHP_BINARY, __FILE__, 'worker', $source, 'event-' . $i],
            [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']], $pipes);
        if (!is_resource($process)) throw new RuntimeException('Could not launch worker');
        fclose($pipes[0]); $workers[]=[$process,$pipes];
    }
    $pdo->commit();
    foreach ($workers as [$process,$pipes]) {
        $out=stream_get_contents($pipes[1]); $err=stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
        if (proc_close($process) !== 0) throw new RuntimeException('Worker failed: ' . $out . $err);
    }
    $s=$pdo->prepare('SELECT COUNT(*) FROM event_evidence WHERE source=?'); $s->execute([$source]);
    if ((int)$s->fetchColumn() !== 6) throw new RuntimeException('Concurrent evidence lost');
    $s=$pdo->prepare('SELECT f.id, f.incident_id, f.is_simulated FROM detection_findings f JOIN event_evidence e ON e.id=f.trigger_evidence_id WHERE e.source=?'); $s->execute([$source]);
    $rows=$s->fetchAll(PDO::FETCH_ASSOC);
    if (count($rows)!==1 || $rows[0]['incident_id']!==null || !(bool)$rows[0]['is_simulated']) throw new RuntimeException('Concurrent threshold lost, duplicated or linked to real case');
    $s=$pdo->prepare('SELECT COUNT(*) FROM detection_finding_evidence WHERE finding_id=?'); $s->execute([$rows[0]['id']]);
    if ((int)$s->fetchColumn()!==5) throw new RuntimeException('Incorrect supporting evidence count');
    echo "PASS: six simultaneous failures persist once each and emit exactly one isolated threshold finding.\n";
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack(); fwrite(STDERR, $e->getMessage() . "\n"); exit(1);
}
