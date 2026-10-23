<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/siem/SourceActivityService.php';
require_once __DIR__.'/../includes/siem/EventEvidenceRepository.php';
function sourceFixture(PDO $pdo, string $source, string $actor, int $receiptOffset, bool $simulation = false, string $message = 'source activity fixture'): int {
    $event = gmdate('Y-m-d H:i:s', time() - 86400 * 30);
    $receipt = gmdate('Y-m-d H:i:s', time() + $receiptOffset);
    $pdo->prepare("INSERT INTO logs (source_ip,severity,category,message,timestamp) VALUES ('192.0.2.90','INFO','Other',?,?)")->execute([$message,$event]);
    $id = (int)$pdo->lastInsertId();
    (new EventEvidenceRepository($pdo))->append($id, ['source'=>$source, 'source_type'=>'sensor', 'source_event_id'=>(string)$id,
        'is_simulated'=>$simulation, 'event_timestamp'=>$event, 'received_at'=>$receipt],
        ['message'=>$message,'timestamp'=>$event], hash('sha256',$source.$id), $actor, null);
    return $id;
}
