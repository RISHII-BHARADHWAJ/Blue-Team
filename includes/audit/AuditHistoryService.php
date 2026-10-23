<?php
declare(strict_types=1);
require_once __DIR__.'/../soar/SoarAuth.php';
require_once __DIR__.'/../soar/notifications/NotificationService.php';

/** Privileged metadata-only audit history. No payload, command target or user-agent disclosure. */
final class AuditHistoryService {
    public const PAGE_SIZE = 25;
    public function __construct(private PDO $pdo) {}

    public function search(array $auth, array $input = [], int $page = 1): array {
        if (($auth['auth_method'] ?? '') !== 'session' || empty($auth['user_id'])) {
            throw new DomainException('A named lead or administrator session is required.');
        }
        $own = !$this->pdo->inTransaction();
        try {
            if ($own) { $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'); $this->pdo->beginTransaction(); }
            // A current locking read also enforces role changes inside an older caller snapshot.
            $stmt = $this->pdo->prepare('SELECT role FROM users WHERE id=? LOCK IN SHARE MODE');
            $stmt->execute([(int)$auth['user_id']]); $role = $stmt->fetchColumn();
            if ($role === false || !SoarAuth::hasPermission(SoarAuth::resolveTier($role),'view_audit')) {
                throw new DomainException('A current lead or administrator account is required to view audit history.');
            }
            $filters = self::filters($input);
            $where = []; $params = [];
            if ($filters['q'] !== '') {
                $needle = '%'.strtr($filters['q'],['!'=>'!!','%'=>'!%','_'=>'!_']).'%';
                $where[] = "(analyst LIKE ? ESCAPE '!' OR action LIKE ? ESCAPE '!')";
                $params[] = $needle; $params[] = $needle;
            }
            if ($filters['action'] !== '') { $where[] = 'BINARY action = ?'; $params[] = $filters['action']; }
            if ($filters['result'] === 'unknown') $where[] = 'result IS NULL';
            elseif ($filters['result'] !== 'all') { $where[] = 'result = ?'; $params[] = $filters['result']; }
            if ($filters['from'] !== '') { $where[] = 'timestamp >= ?'; $params[] = $filters['from'].' 00:00:00'; }
            if ($filters['to'] !== '') { $where[] = 'timestamp <= ?'; $params[] = $filters['to'].' 23:59:59'; }
            $case = null;
            if ($filters['case_id'] !== '') {
                $stmt = $this->pdo->prepare('SELECT id,incident_number,is_simulated FROM incidents WHERE id=?');
                $stmt->execute([(int)$filters['case_id']]); $case = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$case) throw new OutOfBoundsException('Referenced case not found.');
                $where[] = '(BINARY target = ? OR BINARY target = ?)';
                $params[] = 'incident:'.$case['id']; $params[] = $case['incident_number'];
            }
            $from = ' FROM audit_log'.($where ? ' WHERE '.implode(' AND ',$where) : '');
            $stmt = $this->pdo->prepare('SELECT COUNT(*)'.$from); $stmt->execute($params); $total = (int)$stmt->fetchColumn();
            $pages = max(1,(int)ceil($total/self::PAGE_SIZE)); $page = max(1,min($page,$pages));
            $limit = self::PAGE_SIZE; $offset = ($page-1)*$limit; $direction = $filters['sort'] === 'oldest' ? 'ASC' : 'DESC';
            $stmt = $this->pdo->prepare('SELECT id,timestamp,analyst,ip_address,action,result,target'.$from." ORDER BY timestamp $direction,id $direction LIMIT $limit OFFSET $offset");
            $stmt->execute($params); $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $cases = $this->caseReferences($rows);
            $redactor = new NotificationService();
            foreach ($rows as &$row) {
                $row['case'] = $cases[$row['target'] ?? ''] ?? null;
                unset($row['target']);
                foreach (['analyst','action','ip_address'] as $key) $row[$key] = $redactor->redactSecrets((string)($row[$key] ?? ''));
            }
            unset($row);
            if ($own) $this->pdo->commit();
            return ['filters'=>$filters,'rows'=>$rows,'total'=>$total,'page'=>$page,'pages'=>$pages,'case'=>$case];
        } catch (Throwable $e) {
            if ($own && $this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }

    public static function filters(array $input): array {
        $filters = [];
        foreach (['q'=>'','action'=>'','result'=>'all','from'=>'','to'=>'','case_id'=>'','sort'=>'newest'] as $key=>$default) {
            $value = $input[$key] ?? $default;
            if (!is_string($value) || strlen($value) > ($key === 'action' ? 100 : 200) || !preg_match('//u',$value)) throw new InvalidArgumentException('Audit filters must be valid UTF-8 text within their field limits.');
            $filters[$key] = trim($value);
        }
        if (!in_array($filters['result'],['all','success','failure','blocked','unknown'],true) || !in_array($filters['sort'],['newest','oldest'],true)) throw new InvalidArgumentException('Select a valid outcome and sort order.');
        foreach (['from','to'] as $key) {
            if ($filters[$key] === '') continue;
            if (!preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/D',$filters[$key])) throw new InvalidArgumentException('Dates must be valid YYYY-MM-DD dates.');
            $date = DateTimeImmutable::createFromFormat('!Y-m-d',$filters[$key]);
            if (!$date || $date->format('Y-m-d') !== $filters[$key]) throw new InvalidArgumentException('Dates must be valid YYYY-MM-DD dates.');
        }
        if ($filters['from'] !== '' && $filters['to'] !== '' && $filters['from'] > $filters['to']) throw new InvalidArgumentException('Start date must not follow end date.');
        if ($filters['case_id'] !== '' && !filter_var($filters['case_id'],FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])) throw new InvalidArgumentException('Case ID must be a positive integer.');
        return $filters;
    }

    private function caseReferences(array $rows): array {
        $ids = []; $numbers = [];
        foreach ($rows as $row) {
            $target = $row['target'] ?? '';
            if (preg_match('/^incident:([1-9][0-9]*)$/D',$target,$m) && filter_var($m[1],FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])) $ids[] = (int)$m[1];
            elseif (preg_match('/^INC-[0-9]{4}-[0-9]+$/D',$target)) $numbers[] = $target;
        }
        $where = []; $params = [];
        foreach (['id'=>$ids,'incident_number'=>$numbers] as $column=>$values) {
            if ($values) { $where[] = "$column IN (".implode(',',array_fill(0,count($values),'?')).')'; array_push($params,...$values); }
        }
        if (!$where) return [];
        $stmt = $this->pdo->prepare('SELECT id,incident_number,is_simulated FROM incidents WHERE '.implode(' OR ',$where));
        $stmt->execute($params); $map = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $case) {
            $map['incident:'.$case['id']] = $case;
            if (preg_match('/^INC-[0-9]{4}-[0-9]+$/D',$case['incident_number'])) $map[$case['incident_number']] = $case;
        }
        return $map;
    }
}
