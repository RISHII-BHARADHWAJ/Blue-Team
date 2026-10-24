<?php
/** Analyst-authored case notes, with atomic note/timeline/audit persistence. */
declare(strict_types=1);
require_once __DIR__ . '/SoarAuth.php';
require_once __DIR__ . '/IncidentTimeline.php';
final class CaseNoteService
{
    public const MAX_BYTES = 10000;
    public function __construct(private PDO $pdo) {}

    public static function searchText(mixed $value): string {
        if (!is_string($value) || strlen($value)>200 || !preg_match('//u',$value)) throw new InvalidArgumentException('Note search must be valid UTF-8 text of at most 200 bytes.');
        return trim($value);
    }

    public function list(int $incidentId, int $page = 1, string $query = ''): array
    {
        $query=self::searchText($query);
        $own=!$this->pdo->inTransaction();
        try {
            if ($own) {$this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');$this->pdo->beginTransaction();}
            $from=' FROM case_notes n JOIN users u ON u.id=n.author_id WHERE n.incident_id=?';$params=[$incidentId];
            if ($query!=='') {
                $needle='%'.strtr($query,['!'=>'!!','%'=>'!%','_'=>'!_']).'%';
                $from.=" AND (n.note_text LIKE ? ESCAPE '!' OR u.username LIKE ? ESCAPE '!')";
                array_push($params,$needle,$needle);
            }
            $stmt=$this->pdo->prepare('SELECT COUNT(*)'.$from);$stmt->execute($params);$total=(int)$stmt->fetchColumn();
            $pages=max(1,(int)ceil($total/25));$page=max(1,min($page,$pages));$offset=($page-1)*25;
            $stmt=$this->pdo->prepare('SELECT n.id,n.note_text,n.author_id,n.created_at,u.username AS author'.$from.' ORDER BY n.created_at DESC,n.id DESC LIMIT 25 OFFSET '.$offset);
            $stmt->execute($params);$notes=$stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($own) $this->pdo->commit();
            return ['notes'=>$notes,'total'=>$total,'page'=>$page,'pages'=>$pages];
        } catch (Throwable $e) {if($own && $this->pdo->inTransaction())$this->pdo->rollBack();throw $e;}
    }

    /** $authorId must come from verified session/run context, never a request body. */
    public function add(int $incidentId, int $authorId, string $text): array
    {
        if (trim($text) === '' || strlen($text) > self::MAX_BYTES) {
            throw new LengthException('A case note must contain text and be at most 10,000 UTF-8 bytes.');
        }
        if (!preg_match('//u', $text)) throw new LengthException('A case note must contain valid UTF-8 text.');
        $own = !$this->pdo->inTransaction();
        $savepoint = 'note_' . bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $savepoint");
        try {
            $stmt = $this->pdo->prepare('SELECT id FROM incidents WHERE id = ? FOR UPDATE');
            $stmt->execute([$incidentId]);
            if (!$stmt->fetchColumn()) throw new OutOfBoundsException('Incident not found.');
            $stmt = $this->pdo->prepare('SELECT username, role FROM users WHERE id = ?');
            $stmt->execute([$authorId]);
            $author = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$author || !SoarAuth::hasPermission(SoarAuth::resolveTier($author['role']), 'add_notes')) {
                throw new DomainException('A verified user account is required to author case notes.');
            }
            $stmt = $this->pdo->prepare('INSERT INTO case_notes (incident_id, author_id, note_text) VALUES (?, ?, ?)');
            $stmt->execute([$incidentId, $authorId, $text]);
            $noteId = (int)$this->pdo->lastInsertId();
            (new IncidentTimeline($this->pdo))->addEvent($incidentId, 'NOTE_ADDED', 'ANALYST', $author['username'],
                "Case note #$noteId added", ['note_id'=>$noteId, 'author_id'=>$authorId]);
            $stmt = $this->pdo->prepare("INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent)
                VALUES (?, ?, 'add_case_note', ?, 'success', ?, ?)");
            $stmt->execute([
                $author['username'], substr($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', 0, 45), 'incident:' . $incidentId,
                json_encode(['note_id'=>$noteId, 'incident_id'=>$incidentId, 'author_id'=>$authorId], JSON_THROW_ON_ERROR),
                substr($_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-CaseNotes', 0, 500),
            ]);
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
            return ['id'=>$noteId, 'incident_id'=>$incidentId, 'author_id'=>$authorId];
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint"); $this->pdo->exec("RELEASE SAVEPOINT $savepoint"); }
            }
            throw $e;
        }
    }
}
