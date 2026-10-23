<?php
declare(strict_types=1);
require_once __DIR__.'/../SoarAuth.php';
require_once __DIR__.'/../notifications/NotificationService.php';

/** Bounded, read-only queue. Expiration is derived at one database-server time. */
final class ApprovalQueueService {
    public const PAGE_SIZE = 25;
    public function __construct(private PDO $pdo) {}

    public function search(array $auth, array $input = []): array {
        if (($auth['actor'] ?? 'anonymous') === 'anonymous' || !SoarAuth::hasPermission($auth['tier'] ?? 'GUEST','view_incidents')) {
            throw new DomainException('Authentication with incident-view permission is required.');
        }
        $filters = self::filters($input);
        $own = !$this->pdo->inTransaction();
        try {
            if ($own) { $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'); $this->pdo->beginTransaction(); }
            $asOf = (string)$this->pdo->query('SELECT NOW()')->fetchColumn();
            $now = $this->pdo->quote($asOf);
            $effective = "CASE WHEN a.status='PENDING' AND a.expires_at <= $now THEN 'EXPIRED' ELSE a.status END";
            $where = []; $params = [];
            if ($filters['status'] !== '') { $where[] = "($effective) = ?"; $params[] = $filters['status']; }
            if ($filters['priority'] !== '') { $where[] = 'i.priority = ?'; $params[] = $filters['priority']; }
            if ($filters['kind'] !== 'all') { $where[] = 'i.is_simulated = ?'; $params[] = $filters['kind'] === 'simulated' ? 1 : 0; }
            if ($filters['q'] !== '') {
                $needle = '%'.strtr($filters['q'],['!'=>'!!','%'=>'!%','_'=>'!_']).'%';
                $where[] = "(i.incident_number LIKE ? ESCAPE '!' OR i.title LIKE ? ESCAPE '!' OR a.action_name LIKE ? ESCAPE '!' OR a.action_description LIKE ? ESCAPE '!')";
                array_push($params,$needle,$needle,$needle,$needle);
            }
            $from = ' FROM approval_requests a JOIN incidents i ON i.id=a.incident_id'.($where ? ' WHERE '.implode(' AND ',$where) : '');
            $pending = "a.status='PENDING' AND a.expires_at > $now";
            $stmt = $this->pdo->prepare("SELECT COUNT(*) AS total, COALESCE(SUM($pending),0) AS pending, COALESCE(SUM(($pending) AND i.priority IN ('P1','P2')),0) AS critical, COALESCE(SUM(($pending) AND a.expires_at < DATE_ADD($now, INTERVAL 4 HOUR)),0) AS expiring".$from);
            $stmt->execute($params); $counts = array_map('intval',$stmt->fetch(PDO::FETCH_ASSOC));
            $pages = max(1,(int)ceil($counts['total']/self::PAGE_SIZE)); $page = min($filters['page'],$pages);
            $order = match ($filters['sort']) {
                'oldest' => 'a.requested_at ASC,a.id ASC',
                'expiry' => 'a.expires_at ASC,a.id ASC',
                'priority' => "FIELD(i.priority,'P1','P2','P3','P4') ASC,a.requested_at ASC,a.id ASC",
                default => 'a.requested_at DESC,a.id DESC',
            };
            $offset = ($page-1)*self::PAGE_SIZE;
            $stmt = $this->pdo->prepare("SELECT a.id,a.incident_id,a.playbook_run_id,a.action_name,LEFT(a.action_description,300) AS action_description,CHAR_LENGTH(a.action_description)>300 AS description_truncated,a.required_tier,a.status AS stored_status,($effective) AS status,a.requested_at,a.expires_at,TIMESTAMPDIFF(SECOND,$now,a.expires_at) AS expires_in_seconds,i.incident_number,i.title AS incident_title,i.priority AS incident_priority,i.risk_score AS incident_risk_score,i.is_simulated".$from." ORDER BY $order LIMIT ".self::PAGE_SIZE." OFFSET $offset");
            $stmt->execute($params); $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $redactor = new NotificationService();
            foreach ($rows as &$row) {
                foreach (['id','incident_id','playbook_run_id','expires_in_seconds','is_simulated','description_truncated'] as $field) $row[$field] = (int)$row[$field];
                foreach (['incident_title','action_name','action_description'] as $field) $row[$field] = $redactor->redactSecrets($row[$field]);
            }
            unset($row);
            if ($own) $this->pdo->commit();
            $filters['page'] = $page;
            return ['data'=>$rows,'filters'=>$filters,'pagination'=>['total'=>$counts['total'],'page'=>$page,'pages'=>$pages,'per_page'=>self::PAGE_SIZE],'metrics'=>['pending'=>$counts['pending'],'critical'=>$counts['critical'],'expiring'=>$counts['expiring']],'as_of'=>$asOf];
        } catch (Throwable $e) {
            if ($own && $this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }

    public static function filters(array $input): array {
        $out = [];
        foreach (['q'=>'','status'=>'PENDING','priority'=>'','kind'=>'observed','sort'=>'newest'] as $key=>$default) {
            $value = $input[$key] ?? $default;
            if (!is_string($value) || strlen($value)>200 || !preg_match('//u',$value)) throw new InvalidArgumentException('Queue filters must be valid UTF-8 text of at most 200 bytes.');
            $out[$key] = trim($value);
        }
        foreach (['status'=>['','PENDING','APPROVED','REJECTED','EXPIRED','CANCELLED'],'priority'=>['','P1','P2','P3','P4'],'kind'=>['observed','simulated','all'],'sort'=>['newest','oldest','expiry','priority']] as $key=>$allowed) {
            if (!in_array($out[$key],$allowed,true)) throw new InvalidArgumentException('Select valid queue filters.');
        }
        $page = $input['page'] ?? 1;
        if ((!is_string($page) && !is_int($page)) || !filter_var($page,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])) throw new InvalidArgumentException('Page must be a positive integer.');
        $out['page'] = (int)$page;
        return $out;
    }
}
