<?php
declare(strict_types=1);

/** Receipt-based activity for previously observed submitter/source pairs; not sensor health. */
final class SourceActivityService {
    public const PAGE_SIZE = 25;

    public function __construct(private PDO $pdo) {}

    public static function filters(array $input): array {
        $defaults = ['q'=>'', 'kind'=>'observed', 'hours'=>'24', 'activity'=>'all', 'sort'=>'newest'];
        $filters = [];
        foreach ($defaults as $key=>$default) {
            $value = $input[$key] ?? $default;
            if (!is_string($value) || strlen($value) > 200 || !preg_match('//u', $value)) {
                throw new InvalidArgumentException('Source filters must be valid UTF-8 text of at most 200 bytes.');
            }
            $filters[$key] = trim($value);
        }
        foreach (['kind'=>['observed','simulated'], 'hours'=>['1','24','168'],
            'activity'=>['all','recent','quiet','clock'], 'sort'=>['newest','oldest','volume']] as $key=>$allowed) {
            if (!in_array($filters[$key], $allowed, true)) throw new InvalidArgumentException('Select valid source activity filters.');
        }
        return $filters;
    }

    public function search(array $input = [], int $page = 1): array {
        $filters = self::filters($input);
        $own = !$this->pdo->inTransaction();
        try {
            if ($own) {
                $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
                $this->pdo->beginTransaction();
            }
            $hours = (int)$filters['hours'];
            $clock = $this->pdo->query("SELECT UTC_TIMESTAMP() AS as_of_utc,
                DATE_SUB(UTC_TIMESTAMP(), INTERVAL $hours HOUR) AS since_utc")->fetch(PDO::FETCH_ASSOC);
            // Freeze one UTC clock for all aggregates and activity classifications in this request.
            $now = $this->pdo->quote($clock['as_of_utc']);
            $since = $this->pdo->quote($clock['since_utc']);
            $where = ['e.is_simulated = ?'];
            $params = [$filters['kind'] === 'simulated' ? 1 : 0];
            if ($filters['q'] !== '') {
                $needle = '%'.strtr($filters['q'], ['!'=>'!!', '%'=>'!%', '_'=>'!_']).'%';
                $where[] = "(e.source LIKE ? ESCAPE '!' OR e.submitted_by LIKE ? ESCAPE '!')";
                $params[] = $needle; $params[] = $needle;
            }
            $predicate = implode(' AND ', $where);
            // Binary keys prevent two distinct credentials/source spellings from being merged by collation.
            $groups = "SELECT BINARY e.submitted_by AS submitted_by, BINARY e.source AS source,
                COUNT(*) AS stored_count,
                SUM(e.received_at >= $since AND e.received_at <= $now) AS recent_count,
                SUM(e.received_at > $now) AS future_count,
                MIN(CASE WHEN e.received_at <= $now THEN e.received_at END) AS first_received_at,
                MAX(CASE WHEN e.received_at <= $now THEN e.received_at END) AS last_received_at
                FROM event_evidence e JOIN logs l ON l.id = e.log_id WHERE $predicate
                GROUP BY BINARY e.submitted_by, BINARY e.source";
            $classified = "SELECT g.*, CASE WHEN future_count > 0 THEN 'clock'
                WHEN last_received_at >= $since THEN 'recent' ELSE 'quiet' END AS activity FROM ($groups) g";
            $from = " FROM ($classified) activity_groups";
            if ($filters['activity'] !== 'all') { $from .= ' WHERE activity = ?'; $params[] = $filters['activity']; }
            $stmt = $this->pdo->prepare('SELECT COUNT(*)'.$from);
            $stmt->execute($params);
            $total = (int)$stmt->fetchColumn();
            $pages = max(1, (int)ceil($total / self::PAGE_SIZE));
            $page = max(1, min($page, $pages));
            $order = match ($filters['sort']) {
                'oldest'=>'last_received_at IS NULL ASC, last_received_at ASC',
                'volume'=>'recent_count DESC, last_received_at DESC',
                default=>'last_received_at DESC',
            };
            $limit = self::PAGE_SIZE; $offset = ($page - 1) * $limit;
            $stmt = $this->pdo->prepare('SELECT *'.$from." ORDER BY $order, submitted_by ASC, source ASC LIMIT $limit OFFSET $offset");
            $stmt->execute($params);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$row) {
                foreach (['stored_count','recent_count','future_count'] as $key) $row[$key] = (int)$row[$key];
            }
            unset($row);
            if ($own) $this->pdo->commit();
            return $clock + ['filters'=>$filters,'rows'=>$rows,'total'=>$total,'page'=>$page,'pages'=>$pages];
        } catch (Throwable $e) {
            if ($own && $this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }
}
