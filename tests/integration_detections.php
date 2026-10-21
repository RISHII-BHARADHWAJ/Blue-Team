<?php
/** Integration suite for disposable Compose CI; all fixtures rolled back. */
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') {
    fwrite(STDERR, "Refusing to run outside disposable Compose CI.\n"); exit(2);
}
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/soar/SiemSoarAlertPipeline.php';
require_once __DIR__ . '/../includes/siem/DetectionRepository.php';
function detectionCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: ' . $message);
    echo "PASS: $message\n";
}
$pipeline = new SiemSoarAlertPipeline($pdo); $repo = new DetectionRepository($pdo);
$source = 'detection-ci-' . bin2hex(random_bytes(6)); $sequence = 0;
$send = function (array $overrides = [], string $actor = 'ci-detector') use ($pipeline, $source, &$sequence): array {
    $p = array_replace(['source'=>$source, 'source_type'=>'sensor', 'source_event_id'=>'e' . ++$sequence,
        'source_ip'=>'192.0.2.40', 'severity'=>'LOW', 'category'=>'SSH', 'message'=>'Authentication rejected',
        'event_timestamp'=>'2001-01-01T00:00:00Z', 'is_simulated'=>true,
        'metadata'=>['event_type'=>'authentication', 'outcome'=>'failure']], $overrides);
    $r = $pipeline->ingest($p, $actor);
    if (!$r['success'] || !empty($r['duplicate'])) throw new RuntimeException('Fixture not accepted: ' . json_encode($r));
    return $r;
};
$pdo->beginTransaction();
try {
    $pdo->exec("UPDATE detection_rules SET enabled=1, revision=1, threshold_count=5, window_seconds=300, severity='HIGH' WHERE rule_key='auth_failures'");
    $pdo->exec("UPDATE detection_rules SET enabled=1, revision=1, threshold_count=1, window_seconds=3600, severity='MEDIUM' WHERE rule_key='source_ip_intel'");
    detectionCheck(count($repo->rules()) === 2, 'migration seeds two typed rules');
    $first = $send();
    detectionCheck($first['detections'] === [], 'first failure does not meet threshold');
    $duplicate = $pipeline->ingest($first['alert'], 'ci-detector');
    detectionCheck(!empty($duplicate['duplicate']), 'retry is deduplicated before rule counting');
    $success = $send(['metadata'=>['event_type'=>'authentication', 'outcome'=>'success']]);
    $textOnly = $send(['metadata'=>[]]);
    detectionCheck(!$success['detections'] && !$textOnly['detections'], 'successful auth and message-only failures excluded');
    for ($i=0; $i<3; $i++) detectionCheck($send()['detections'] === [], 'below threshold has no finding');
    detectionCheck($send(['source'=>$source . '-other'])['detections'] === [], 'different claimed source isolated');
    detectionCheck($send([], 'other-submitter')['detections'] === [], 'different authenticated submitter isolated');
    detectionCheck($send(['source_type'=>'other-sensor'])['detections'] === [], 'different source type isolated');
    detectionCheck($send(['source_ip'=>'192.0.2.41'])['detections'] === [], 'different source IP isolated');
    $real = $send(['is_simulated'=>false]);
    detectionCheck(!$real['detections'] && $real['correlation']['incident_id'] === null, 'simulated failures cannot advance real threshold');
    $fifth = $send(['event_timestamp'=>'2090-01-01T00:00:00Z']);
    detectionCheck(count($fifth['detections']) === 1 && $fifth['correlation']['incident_id'] === null, 'receipt window ignores old/future source dates; simulated finding has no case');
    $finding = $repo->find($fifth['detections'][0]['id']);
    detectionCheck(count($finding['evidence']) === 5 && (int)$finding['is_simulated'] === 1 && $finding['incident_id'] === null, 'threshold evidence and simulation label preserved');
    $snapshot = json_decode($finding['rule_snapshot'], true);
    detectionCheck((int)$snapshot['threshold_count'] === 5 && $snapshot['severity'] === 'HIGH', 'settings snapshot retained');
    detectionCheck($send()['detections'] === [], 'cooldown suppresses repeat findings');
    // Force a closed receipt window without waiting in real time.
    $pdo->prepare("UPDATE detection_findings SET created_at=DATE_SUB(UTC_TIMESTAMP(), INTERVAL 301 SECOND) WHERE id=?")->execute([$finding['id']]);
    $pdo->prepare("UPDATE detection_observations SET received_at=DATE_SUB(UTC_TIMESTAMP(), INTERVAL 301 SECOND) WHERE group_key=?")
        ->execute([DetectionEngine::groupKey($fifth['alert'], 'ci-detector')]);
    detectionCheck($send()['detections'] === [], 'expired observations do not satisfy a new window');
    for ($i=0; $i<3; $i++) $send();
    detectionCheck(count($send()['detections']) === 1, 'new qualifying window emits after cooldown');
    // LOW evidence becomes a HIGH incident from the rule, not an evidence rewrite.
    for ($i=0; $i<3; $i++) $send(['is_simulated'=>false]);
    $realFinding = $send(['is_simulated'=>false]);
    detectionCheck(count($realFinding['detections']) === 1 && $realFinding['correlation']['incident_id'] !== null, 'real threshold escalates low sensor events into a case');
    $evidence = (new EventEvidenceRepository($pdo))->findByLogId($realFinding['log_id']);
    detectionCheck($evidence['severity'] === 'LOW' && json_decode($evidence['canonical_json'], true)['severity'] === 'LOW', 'stored source severity stays unchanged');
    detectionCheck((int)$repo->find($realFinding['detections'][0]['id'])['incident_id'] === $realFinding['correlation']['incident_id'], 'finding links to correlated incident');

    $userStmt = $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?, ?, ?)');
    $userStmt->execute([$source . '-admin', 'not-a-login-hash', 'admin']); $adminId=(int)$pdo->lastInsertId();
    $userStmt->execute([$source . '-user', 'not-a-login-hash', 'user']); $readerId=(int)$pdo->lastInsertId();
    $settings = ['enabled'=>'0','severity'=>'MEDIUM','threshold_count'=>'2','window_seconds'=>'60','revision'=>'1'];
    $denied=false; try { $repo->updateRule('auth_failures', $settings, $readerId); } catch (UnexpectedValueException $e) { $denied=true; }
    detectionCheck($denied && $pdo->inTransaction(), 'non-admin cannot configure rules; outer transaction survives');
    $repo->updateRule('auth_failures', $settings, $adminId);
    $audit = $pdo->prepare("SELECT details FROM audit_log WHERE analyst=? AND action='update_detection_rule' ORDER BY id DESC LIMIT 1");
    $audit->execute([$source . '-admin']);
    detectionCheck((int)json_decode($audit->fetchColumn(), true)['after']['revision'] === 2, 'configuration edit audited with a new revision');
    detectionCheck($repo->find($finding['id'])['rule_snapshot'] === $finding['rule_snapshot'], 'configuration changes preserve historical settings');
    detectionCheck($send()['detections'] === [], 'disabled rule does not emit');
    $stale=false; try { $repo->updateRule('auth_failures', $settings, $adminId); } catch (DomainException $e) { $stale=true; }
    detectionCheck($stale, 'stale settings update rejected');
    $invalid=false; try { $repo->updateRule('auth_failures', array_replace($settings, ['threshold_count'=>'101']), $adminId); } catch (InvalidArgumentException $e) { $invalid=true; }
    detectionCheck($invalid, 'threshold bounded to prevent unbounded evidence selection');
    $settings['enabled']='1'; $settings['revision']='2'; $repo->updateRule('auth_failures', $settings, $adminId);
    detectionCheck(count($send()['detections']) === 1, 'new revision uses updated threshold and counts retained observations');

    $intelIp = '198.51.100.88';
    $pdo->prepare("INSERT INTO threat_feed_indicators (provider,indicator_type,indicator_value,threat_type,fetched_at)
        VALUES (?, 'IPV4', ?, 'ci-reputation', UTC_TIMESTAMP())")->execute([$source, $intelIp]);
    $intel = $send(['source_ip'=>$intelIp, 'metadata'=>[]]);
    detectionCheck(count($intel['detections']) === 1 && $intel['detections'][0]['rule_key'] === 'source_ip_intel', 'intel rule requires an accepted matching source-IP event');
    $intelDetail = $repo->find($intel['detections'][0]['id']); $context = json_decode($intelDetail['context_json'], true);
    detectionCheck($context['intelligence_matches'][0]['provider'] === $source && count($intelDetail['evidence']) === 1, 'intelligence provider and local evidence retained together');
    detectionCheck($send(['source_ip'=>$intelIp, 'metadata'=>[]])['detections'] === [], 'intelligence findings respect cooldown');
    detectionCheck($send(['source_ip'=>null, 'metadata'=>[]])['detections'] === [], 'missing source IP cannot match');

    // Roll back a fully evaluated result and retry through the same service instance.
    $rollbackSource = $source . '-rollback'; $send(['source'=>$rollbackSource]);
    $pdo->exec('SAVEPOINT detection_retry');
    $rolled = $send(['source'=>$rollbackSource]);
    detectionCheck(count($rolled['detections']) === 1, 'rollback fixture produced a finding');
    $pdo->exec('ROLLBACK TO SAVEPOINT detection_retry');
    detectionCheck($repo->find($rolled['detections'][0]['id']) === null, 'caller rollback removes finding and supporting links');
    $retry = $pipeline->ingest($rolled['alert'], 'ci-detector');
    detectionCheck(!empty($retry['success']) && empty($retry['duplicate']) && count($retry['detections']) === 1, 'retry after rollback counts once and recreates finding');
    $list = $repo->findings('simulated', 999999);
    detectionCheck($list['page'] === $list['pages'] && count($list['rows']) > 0, 'finding pagination clamps to final page');
    foreach ($repo->findings('observed', 1)['rows'] as $r) detectionCheck(!(bool)$r['is_simulated'], 'default observed filter excludes simulations');
    $pdo->rollBack(); echo "Detection integration passed; fixtures rolled back.\n";
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack(); fwrite(STDERR, $e->getMessage() . "\n"); exit(1);
}
