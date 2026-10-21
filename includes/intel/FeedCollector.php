<?php
declare(strict_types=1);
require_once __DIR__ . '/FeedCatalog.php';
/** Connection-owned provider lock spans fetch + commit; network occurs outside transactions. */
final class FeedCollector
{
    private Closure $fetch;
    public function __construct(private PDO $pdo, ?callable $fetch = null)
    {
        $this->fetch=$fetch===null ? Closure::fromCallable([FeedCatalog::class,'download']) : Closure::fromCallable($fetch);
    }
    public function collect(string $provider, bool $scheduled=false): array
    {
        $config=FeedCatalog::get($provider);
        if ($this->pdo->inTransaction()) throw new LogicException('Collector needs its own connection outside a transaction.');
        $database=(string)$this->pdo->query('SELECT DATABASE()')->fetchColumn();
        $lock=FeedCatalog::lockName($database, $provider);
        $stmt=$this->pdo->prepare('SELECT GET_LOCK(?, 0)'); $stmt->execute([$lock]);
        if ((int)$stmt->fetchColumn()!==1) return ['provider'=>$provider,'status'=>'SKIPPED','detail'=>'Another collection is running.'];
        $runId=null; $http=null; $bytes=0; $started=microtime(true);
        try {
            // Reconcile an interrupted process after acquiring its released connection lock.
            $this->pdo->prepare("UPDATE feed_collection_runs SET status='INTERRUPTED', finished_at=UTC_TIMESTAMP(),
                detail='Previous collector exited without a recorded result.' WHERE provider=? AND status='RUNNING'")->execute([$provider]);
            $this->pdo->beginTransaction();
            $stmt=$this->pdo->prepare('SELECT *, (last_attempt_at IS NULL OR TIMESTAMPDIFF(SECOND,last_attempt_at,UTC_TIMESTAMP()) >= refresh_seconds) AS due
                FROM feed_sources WHERE provider=? FOR UPDATE'); $stmt->execute([$provider]); $source=$stmt->fetch(PDO::FETCH_ASSOC);
            if (!$source) throw new RuntimeException('Feed settings missing; apply migration 010.');
            if (!(bool)$source['enabled'] || ($scheduled && !(bool)$source['due'])) {
                $this->pdo->commit();
                return ['provider'=>$provider,'status'=>'SKIPPED','detail'=>$source['enabled']?'Not due yet.':'Feed disabled.'];
            }
            $stmt=$this->pdo->prepare("INSERT INTO feed_collection_runs (provider,source_url,trigger_kind,config_revision,status,started_at,detail)
                VALUES (?, ?, ?, ?, 'RUNNING', UTC_TIMESTAMP(), 'Collection started.')");
            $stmt->execute([$provider,$config['url'],$scheduled?'SCHEDULED':'MANUAL',$source['revision']]); $runId=(int)$this->pdo->lastInsertId();
            $this->pdo->prepare('UPDATE feed_sources SET last_attempt_at=UTC_TIMESTAMP() WHERE provider=?')->execute([$provider]);
            $this->pdo->commit();
            $response=($this->fetch)($config['url']);
            $http=is_int($response['status'] ?? null) ? $response['status'] : null;
            $raw=$response['body'] ?? false;
            $bytes=is_string($raw) ? strlen($raw) : 0;
            if (!is_string($raw)) throw new UnexpectedValueException('Feed transport failed or timed out.');
            if ($http!==200) throw new UnexpectedValueException('Feed returned HTTP ' . ($http ?? 'unknown') . '; expected 200.');
            $parsed=FeedCatalog::parse($provider,$raw);
            $this->pdo->beginTransaction(); $new=0;
            $stmt=$this->pdo->prepare("INSERT INTO threat_feed_indicators
                (provider,indicator_type,indicator_value,threat_type,malware_family,port,source_first_seen,source_last_seen,fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE
                threat_type=VALUES(threat_type), malware_family=VALUES(malware_family), port=VALUES(port),
                source_first_seen=COALESCE(VALUES(source_first_seen),source_first_seen),
                source_last_seen=COALESCE(VALUES(source_last_seen),source_last_seen), fetched_at=UTC_TIMESTAMP()");
            foreach ($parsed['rows'] as $row) {
                $stmt->execute([$provider,$row['type'],$row['ip'],$provider==='feodo_tracker'?'botnet_c2':'reported_malicious_ip',
                    $row['malware'],$row['port'],$row['first'],$row['last']]);
                if ($stmt->rowCount()===1) $new++;
            }
            $count=count($parsed['rows']); $status=$parsed['truncated'] || $parsed['invalid']>0 ? 'PARTIAL' : 'SUCCESS';
            $detail=$status==='SUCCESS' ? 'Collection committed.' : 'Collection committed with omitted rows; inspect invalid count and cap flag.';
            $stmt=$this->pdo->prepare('UPDATE feed_collection_runs SET status=?, finished_at=UTC_TIMESTAMP(), http_status=?, bytes_received=?,
                processed_count=?, inserted_count=?, existing_count=?, invalid_count=?, duplicate_count=?, truncated=?, elapsed_ms=?, detail=? WHERE id=?');
            $stmt->execute([$status,$http,$bytes,$count,$new,$count-$new,$parsed['invalid'],$parsed['duplicates'],(int)$parsed['truncated'],
                (int)round((microtime(true)-$started)*1000),$detail,$runId]);
            if ($status==='SUCCESS') $this->pdo->prepare('UPDATE feed_sources SET last_success_at=UTC_TIMESTAMP() WHERE provider=?')->execute([$provider]);
            $this->pdo->commit();
            return ['provider'=>$provider,'id'=>$runId,'status'=>$status,'processed'=>$count,'inserted'=>$new,'detail'=>$detail];
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) $this->pdo->rollBack();
            // Never persist raw remote bodies, SQL error text, secrets or transport exception messages.
            $detail=$e instanceof UnexpectedValueException ? $e->getMessage() : 'Collection could not be committed; check database health and migrations.';
            if ($runId!==null) {
                $stmt=$this->pdo->prepare("UPDATE feed_collection_runs SET status='FAILED',finished_at=UTC_TIMESTAMP(),http_status=?,
                    bytes_received=?,elapsed_ms=?,detail=? WHERE id=?");
                $stmt->execute([$http,min($bytes,FeedCatalog::MAX_BYTES+1),(int)round((microtime(true)-$started)*1000),$detail,$runId]);
            }
            return ['provider'=>$provider,'id'=>$runId,'status'=>'FAILED','processed'=>0,'inserted'=>0,'detail'=>$detail];
        } finally {
            $stmt=$this->pdo->prepare('SELECT RELEASE_LOCK(?)'); $stmt->execute([$lock]);
        }
    }
}
