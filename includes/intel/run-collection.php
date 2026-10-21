<?php
/** Shared CLI runner for the existing collector entry points. */
declare(strict_types=1);
require_once __DIR__ . '/FeedCollector.php';
function runFeedCollection(array $providers, array $args): int
{
    if (array_diff($args,['--scheduled'])) { fwrite(STDERR,"Usage: php collector.php [--scheduled]\n"); return 2; }
    if (getenv('FEED_COLLECTION_ENABLED')==='0') { echo "[ThreatIntel] Collection paused by deployment setting.\n"; return 0; }
    try {
        $host=getenv('DB_HOST')?:'localhost'; $database=getenv('DB_NAME')?:'cybertech_db';
        $pdo=new PDO("mysql:host=$host;dbname=$database;charset=utf8mb4",getenv('DB_USER')?:'redteam_user',getenv('DB_PASS')?:'root',
            [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);
    } catch (Throwable $e) { fwrite(STDERR,"[ThreatIntel] Database unavailable; no collection attempted.\n"); return 1; }
    $collector=new FeedCollector($pdo); $failed=false;
    foreach ($providers as $provider) {
        try {
            $r=$collector->collect($provider,in_array('--scheduled',$args,true));
            echo '[ThreatIntel] '.json_encode($r,JSON_UNESCAPED_SLASHES)."\n";
            if (in_array($r['status'],['FAILED','PARTIAL'],true)) $failed=true;
        } catch (Throwable $e) { fwrite(STDERR,"[ThreatIntel] $provider: collection unavailable; check database health and migrations 007/010.\n"); $failed=true; }
    }
    return $failed?1:0;
}
