<?php
declare(strict_types=1);
require_once __DIR__ . '/FeedCatalog.php';
require_once __DIR__ . '/../soar/SoarAuth.php';
final class FeedRepository
{
    public function __construct(private PDO $pdo) {}
    public function sources(): array
    {
        $rows=$this->pdo->query('SELECT s.*, r.id AS run_id, r.status AS run_status, r.finished_at, r.detail,
            TIMESTAMPDIFF(SECOND,s.last_attempt_at,UTC_TIMESTAMP()) AS attempt_age,
            DATE_ADD(s.last_attempt_at,INTERVAL s.refresh_seconds SECOND) AS next_due_at
            FROM feed_sources s LEFT JOIN feed_collection_runs r ON r.id=(SELECT MAX(r2.id) FROM feed_collection_runs r2 WHERE r2.provider=s.provider)
            ORDER BY s.provider')->fetchAll(PDO::FETCH_ASSOC);
        $db=(string)$this->pdo->query('SELECT DATABASE()')->fetchColumn();
        foreach ($rows as &$row) {
            if (!isset(FeedCatalog::FEEDS[$row['provider']])) { $row['health']='UNSUPPORTED'; continue; }
            if (!(bool)$row['enabled']) $row['health']='DISABLED';
            elseif ($row['run_status']==='RUNNING') {
                $stmt=$this->pdo->prepare('SELECT IS_USED_LOCK(?)'); $stmt->execute([FeedCatalog::lockName($db,$row['provider'])]);
                $row['health']=$stmt->fetchColumn()!==null ? 'RUNNING' : 'INTERRUPTED';
            } elseif ($row['run_id']===null) $row['health']='NEVER_RUN';
            elseif (in_array($row['run_status'],['FAILED','INTERRUPTED'],true)) $row['health']=$row['run_status'];
            elseif ((int)$row['attempt_age']>(int)$row['refresh_seconds']+120) $row['health']='OVERDUE';
            else $row['health']=$row['run_status']==='PARTIAL'?'PARTIAL':'HEALTHY';
        }
        return $rows;
    }
    public function history(string $provider, string $status, int $page): array
    {
        $where=[]; $values=[];
        if ($provider!=='') { FeedCatalog::get($provider); $where[]='provider=?'; $values[]=$provider; }
        if ($status!=='') {
            if (!in_array($status,['RUNNING','SUCCESS','PARTIAL','FAILED','INTERRUPTED'],true)) throw new InvalidArgumentException('Unknown run status.');
            $where[]='status=?'; $values[]=$status;
        }
        $sql=' FROM feed_collection_runs' . ($where?' WHERE '.implode(' AND ',$where):'');
        $stmt=$this->pdo->prepare('SELECT COUNT(*)'.$sql); $stmt->execute($values); $total=(int)$stmt->fetchColumn();
        $pages=max(1,(int)ceil($total/25)); $page=max(1,min($page,$pages));
        $stmt=$this->pdo->prepare('SELECT *'.$sql.' ORDER BY id DESC LIMIT 25 OFFSET ?');
        foreach ($values as $i=>$value) $stmt->bindValue($i+1,$value);
        $stmt->bindValue(count($values)+1,($page-1)*25,PDO::PARAM_INT); $stmt->execute();
        return ['rows'=>$stmt->fetchAll(PDO::FETCH_ASSOC),'page'=>$page,'pages'=>$pages,'total'=>$total];
    }
    public function configure(string $provider, array $input, int $userId): void
    {
        FeedCatalog::get($provider);
        $interval=filter_var($input['refresh_seconds']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>60,'max_range'=>86400]]);
        $revision=filter_var($input['revision']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        $enabled=$input['enabled']??null;
        if (!$interval || !$revision || !in_array($enabled,['0','1'],true)) throw new InvalidArgumentException('Refresh must be 60–86400 seconds with a valid status and revision.');
        $own=!$this->pdo->inTransaction(); $savepoint='feed_config_'.bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $savepoint");
        try {
            $stmt=$this->pdo->prepare('SELECT * FROM feed_sources WHERE provider=? FOR UPDATE'); $stmt->execute([$provider]); $before=$stmt->fetch(PDO::FETCH_ASSOC);
            if (!$before || (int)$before['revision']!==$revision) throw new DomainException('Settings changed. Reload before saving.');
            $stmt=$this->pdo->prepare('SELECT username,role FROM users WHERE id=?'); $stmt->execute([$userId]); $user=$stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']),'admin_operations')) throw new UnexpectedValueException('A current administrator account is required.');
            $this->pdo->prepare('UPDATE feed_sources SET enabled=?,refresh_seconds=?,revision=revision+1,updated_at=UTC_TIMESTAMP(),updated_by=? WHERE provider=?')
                ->execute([(int)$enabled,$interval,$user['username'],$provider]);
            $after=['enabled'=>(int)$enabled,'refresh_seconds'=>$interval,'revision'=>$revision+1];
            $this->pdo->prepare("INSERT INTO audit_log (analyst,ip_address,action,target,result,details,user_agent) VALUES (?,?,'configure_feed',?,'success',?,?)")
                ->execute([$user['username'],substr($_SERVER['REMOTE_ADDR']??'127.0.0.1',0,45),$provider,
                    json_encode(['before'=>$before,'after'=>$after],JSON_THROW_ON_ERROR),substr($_SERVER['HTTP_USER_AGENT']??'ThreatPulse-Feeds',0,500)]);
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint"); $this->pdo->exec("RELEASE SAVEPOINT $savepoint"); }
            }
            throw $e;
        }
    }
}
