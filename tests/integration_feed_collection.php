<?php
/** Committing fixture tests ONLY in disposable CI; never contact external feeds. */
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db') exit(2);
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/intel/FeedCollector.php';
require_once __DIR__ . '/../includes/intel/FeedRepository.php';
function feedCheck(bool $ok,string $label):void { if(!$ok) throw new RuntimeException('FAIL: '.$label); echo "PASS: $label\n"; }
function runRow(PDO $pdo,int $id):array { $s=$pdo->prepare('SELECT * FROM feed_collection_runs WHERE id=?');$s->execute([$id]);return $s->fetch(PDO::FETCH_ASSOC); }
$provider='emerging_threats'; $repo=new FeedRepository($pdo); $calls=0;
$fetch=function(string $url)use(&$calls):array { $calls++; return ['status'=>200,'body'=>"8.8.8.8\n8.8.8.8\n"]; };
$collector=new FeedCollector($pdo,$fetch);$other=null;
try {
    $pdo->exec("UPDATE feed_sources SET enabled=1,refresh_seconds=1800,last_attempt_at=NULL,last_success_at=NULL,revision=1");
    $before=(int)$pdo->query('SELECT COUNT(*) FROM logs')->fetchColumn();
    $r=$collector->collect($provider,true);$row=runRow($pdo,$r['id']);
    feedCheck($r['status']==='SUCCESS' && (int)$row['processed_count']===1 && (int)$row['inserted_count']===1 && (int)$row['duplicate_count']===1,'successful collection stores durable counts and deduplicates feed rows');
    feedCheck($row['trigger_kind']==='SCHEDULED' && (int)$row['http_status']===200 && $row['finished_at']!==null,'run provenance and finish time recorded');
    $r=$collector->collect($provider,true);feedCheck($r['status']==='SKIPPED'&&$calls===1,'not-due scheduled run makes no network request');
    $r=$collector->collect($provider,false);$row=runRow($pdo,$r['id']);
    feedCheck((int)$row['inserted_count']===0&&(int)$row['existing_count']===1,'manual collection bypasses interval and counts existing indicators');
    $pdo->exec("UPDATE feed_sources SET enabled=0 WHERE provider='emerging_threats'");
    $r=$collector->collect($provider);feedCheck($r['status']==='SKIPPED'&&$calls===2,'manual collection honors disabled setting');
    $pdo->exec("UPDATE feed_sources SET enabled=1 WHERE provider='emerging_threats'");
    $failure=new FeedCollector($pdo,fn()=>['status'=>503,'body'=>'<script>secret response</script>']);
    $r=$failure->collect($provider);$row=runRow($pdo,$r['id']);
    feedCheck($r['status']==='FAILED'&&(int)$row['http_status']===503&&!str_contains($row['detail'],'secret'),'HTTP failure recorded without remote body');
    $s=$pdo->prepare('SELECT COUNT(*) FROM threat_feed_indicators WHERE provider=?');$s->execute([$provider]);feedCheck((int)$s->fetchColumn()===1,'failed fetch preserves prior inventory');
    $bad=new FeedCollector($pdo,fn()=>['status'=>200,'body'=>'<html>Unavailable</html>']);
    feedCheck($bad->collect($provider)['status']==='FAILED','malformed successful HTTP response is still a failed collection');
    $partial=new FeedCollector($pdo,fn()=>['status'=>200,'body'=>"8.8.8.8\ninvalid\n"]);
    $r=$partial->collect($provider);feedCheck($r['status']==='PARTIAL'&&(int)runRow($pdo,$r['id'])['invalid_count']===1,'partial import surfaces omitted invalid rows');
    $beforeSuccess=$pdo->query("SELECT last_success_at FROM feed_sources WHERE provider='emerging_threats'")->fetchColumn();
    $pdo->exec("UPDATE feed_sources SET last_success_at='2000-01-01 00:00:00' WHERE provider='emerging_threats'");
    $partial->collect($provider);
    feedCheck($pdo->query("SELECT last_success_at FROM feed_sources WHERE provider='emerging_threats'")->fetchColumn()==='2000-01-01 00:00:00','partial import cannot overwrite last complete success');
    // Another connection must neither fetch nor create a competing run.
    $other=new PDO('mysql:host=db;dbname='.getenv('DB_NAME').';charset=utf8mb4',getenv('DB_USER'),getenv('DB_PASS'),[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $lock=FeedCatalog::lockName((string)$pdo->query('SELECT DATABASE()')->fetchColumn(),$provider);
    $s=$other->prepare('SELECT GET_LOCK(?,0)');$s->execute([$lock]);feedCheck((int)$s->fetchColumn()===1,'test holds provider lock on second connection');
    $r=$collector->collect($provider);feedCheck($r['status']==='SKIPPED'&&$calls===2,'overlapping collector is skipped without fetching');
    $other->prepare('SELECT RELEASE_LOCK(?)')->execute([$lock]);
    // Persist a crashed attempt; next owner reconciles it without pretending success.
    $pdo->prepare("INSERT INTO feed_collection_runs (provider,source_url,trigger_kind,config_revision,status,detail) VALUES (?,?,'SCHEDULED',1,'RUNNING','Interrupted test')")->execute([$provider,FeedCatalog::get($provider)['url']]);$interrupted=(int)$pdo->lastInsertId();
    $health=array_column($repo->sources(),null,'provider');feedCheck($health[$provider]['health']==='INTERRUPTED','orphaned running attempt is shown as interrupted');
    $collector->collect($provider);feedCheck(runRow($pdo,$interrupted)['status']==='INTERRUPTED','next lock owner persists interrupted outcome');
    $health=array_column($repo->sources(),null,'provider');feedCheck($health[$provider]['health']==='HEALTHY','complete recent run is healthy');
    $pdo->exec("UPDATE feed_sources SET last_attempt_at=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 DAY) WHERE provider='emerging_threats'");
    $health=array_column($repo->sources(),null,'provider');feedCheck($health[$provider]['health']==='OVERDUE','missed schedule is visible without another run');
    // Force a write failure after an earlier insert in the same run.
    $pdo->exec("CREATE TRIGGER ci_feed_write_failure BEFORE INSERT ON threat_feed_indicators FOR EACH ROW
        BEGIN IF NEW.provider='emerging_threats' AND NEW.indicator_value='8.8.4.4' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture-secret'; END IF; END");
    $atomic=new FeedCollector($pdo,fn()=>['status'=>200,'body'=>"9.9.9.9\n8.8.4.4\n"]);
    $r=$atomic->collect($provider);$row=runRow($pdo,$r['id']);
    feedCheck($r['status']==='FAILED'&&(int)$row['processed_count']===0&&!str_contains($row['detail'],'fixture-secret'),'database failure records zero committed counts and safe error');
    $s=$pdo->prepare("SELECT COUNT(*) FROM threat_feed_indicators WHERE provider=? AND indicator_value='9.9.9.9'");$s->execute([$provider]);feedCheck((int)$s->fetchColumn()===0,'failed write rolls back earlier indicator inserts');
    $pdo->exec('DROP TRIGGER ci_feed_write_failure');
    feedCheck($atomic->collect($provider)['status']==='SUCCESS','retry can acquire released lock and commit');
    $empty=new FeedCollector($pdo,fn()=>['status'=>200,'body'=>'[]']);
    feedCheck($empty->collect('feodo_tracker')['status']==='SUCCESS','explicit empty Feodo feed is a recorded complete result');
    $user='feed-admin-'.bin2hex(random_bytes(5));$pdo->prepare('INSERT INTO users (username,password,role) VALUES (?, ?, ?)')->execute([$user,'not-a-login-hash','admin']);$admin=(int)$pdo->lastInsertId();
    $settings=['enabled'=>'1','refresh_seconds'=>'60','revision'=>'1'];$repo->configure($provider,$settings,$admin);
    $r=$repo->history($provider,'FAILED',999);feedCheck($r['total']>=3&&$r['page']===$r['pages'],'history filtering and bounded pagination');
    $audit=$pdo->prepare("SELECT details FROM audit_log WHERE analyst=? AND action='configure_feed'");$audit->execute([$user]);feedCheck((int)json_decode($audit->fetchColumn(),true)['after']['refresh_seconds']===60,'settings edits audited');
    $conflict=false;try{$repo->configure($provider,$settings,$admin);}catch(DomainException $e){$conflict=true;}feedCheck($conflict,'stale configuration rejected');
    $pdo->prepare("UPDATE users SET role='user' WHERE id=?")->execute([$admin]);$settings['revision']='2';
    $denied=false;try{$repo->configure($provider,$settings,$admin);}catch(UnexpectedValueException $e){$denied=true;}feedCheck($denied,'revoked administrator rejected by current database role');
    $pdo->exec(file_get_contents(__DIR__.'/../database/migrations/010_feed_collection_history.sql'));
    feedCheck((int)$pdo->query("SELECT refresh_seconds FROM feed_sources WHERE provider='emerging_threats'")->fetchColumn()===60,'rerunning migration preserves operator settings');
    feedCheck((int)$pdo->query('SELECT COUNT(*) FROM logs')->fetchColumn()===$before,'collection creates no observed SIEM events');
    echo "Feed collection integration passed in disposable fixture database.\n";
} catch(Throwable $e) {
    if($pdo->inTransaction())$pdo->rollBack();$pdo->exec('DROP TRIGGER IF EXISTS ci_feed_write_failure');
    fwrite(STDERR,$e->getMessage()."\n");exit(1);
}
