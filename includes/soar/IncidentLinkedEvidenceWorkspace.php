<?php
declare(strict_types=1);
require_once __DIR__.'/IncidentRepository.php';

/** Read-only browsing of existing case associations, including legacy provenance gaps. */
final class IncidentLinkedEvidenceWorkspace {
    public const PAGE_SIZE = 25;
    public function __construct(private PDO $pdo) {}

    public function view(int $id, array $input = [], int $page = 1): array {
        $filters = [];
        foreach (['q'=>'','source_ip'=>'','severity'=>'','provenance'=>'all','sort'=>'event_newest'] as $key=>$default) {
            $value = $input[$key] ?? $default;
            if (!is_string($value) || strlen($value) > ($key === 'source_ip' ? 45 : 200) || !preg_match('//u',$value)) {
                throw new InvalidArgumentException('Search fields must be valid UTF-8 text, at most 200 bytes (45 for source IP).');
            }
            $filters[$key] = trim($value);
        }
        foreach (['severity'=>['','CRITICAL','HIGH','MEDIUM','LOW','INFO'], 'provenance'=>['all','preserved','legacy'],
            'sort'=>['event_newest','event_oldest','attached_newest']] as $key=>$allowed) {
            if (!in_array($filters[$key],$allowed,true)) throw new InvalidArgumentException('Select valid evidence filters.');
        }
        if ($id < 1) throw new InvalidArgumentException('Select a valid incident.');
        $own = !$this->pdo->inTransaction();
        try {
            if ($own) {
                $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
                $this->pdo->beginTransaction();
            }
            $case = (new IncidentRepository($this->pdo))->find($id);
            if (!$case) throw new OutOfBoundsException('Incident not found.');
            $where = ['ia.incident_id = ?']; $params = [$id];
            if ($filters['source_ip'] !== '') { $where[] = 'l.source_ip = ?'; $params[] = $filters['source_ip']; }
            if ($filters['severity'] !== '') {
                $where[] = 'l.severity = ?'; $params[] = $filters['severity'] === 'MEDIUM' ? 'WARNING' : $filters['severity'];
            }
            if ($filters['provenance'] !== 'all') $where[] = 'e.id IS '.($filters['provenance'] === 'legacy' ? '' : 'NOT ').'NULL';
            if ($filters['q'] !== '') {
                $needle = '%'.strtr($filters['q'],['!'=>'!!','%'=>'!%','_'=>'!_']).'%';
                $where[] = "(l.message LIKE ? ESCAPE '!' OR e.source_event_id LIKE ? ESCAPE '!')";
                $params[] = $needle; $params[] = $needle;
            }
            $from = ' FROM incident_alerts ia JOIN logs l ON l.id=ia.log_id LEFT JOIN event_evidence e ON e.log_id=l.id WHERE '.implode(' AND ',$where);
            $stmt = $this->pdo->prepare('SELECT COUNT(*)'.$from); $stmt->execute($params);
            $total = (int)$stmt->fetchColumn(); $pages = max(1,(int)ceil($total/self::PAGE_SIZE));
            $page = max(1,min($page,$pages)); $limit = self::PAGE_SIZE; $offset = ($page-1)*$limit;
            $order = match ($filters['sort']) {
                'event_oldest'=>'COALESCE(e.event_timestamp,l.timestamp) ASC, ia.id ASC',
                'attached_newest'=>'ia.added_at DESC, ia.id DESC',
                default=>'COALESCE(e.event_timestamp,l.timestamp) DESC, ia.id DESC',
            };
            $stmt = $this->pdo->prepare('SELECT ia.id AS junction_id, ia.correlation_rule, ia.added_at AS attached_at,
                l.id AS log_id, l.source_ip, l.severity, l.category, LEFT(l.message,500) AS message,
                CHAR_LENGTH(l.message)>500 AS message_truncated, COALESCE(e.event_timestamp,l.timestamp) AS event_timestamp,
                e.id AS evidence_id, e.source, e.submitted_by, e.source_event_id, e.received_at, e.is_simulated'.$from.
                " ORDER BY $order LIMIT $limit OFFSET $offset");
            $stmt->execute($params); $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($own) $this->pdo->commit();
            return ['incident'=>$case,'filters'=>$filters,'rows'=>$rows,'total'=>$total,'page'=>$page,'pages'=>$pages];
        } catch (Throwable $e) {
            if ($own && $this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }
}
