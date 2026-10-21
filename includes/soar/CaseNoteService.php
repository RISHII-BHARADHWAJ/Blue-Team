<?php
/** Analyst-authored case notes, with atomic note/timeline/audit persistence. */
declare(strict_types=1);
require_once __DIR__ . '/SoarAuth.php';
require_once __DIR__ . '/IncidentTimeline.php';
final class CaseNoteService
{
    public const MAX_BYTES = 10000;
    public function __construct(private PDO $pdo) {}

    public function list(int $incidentId, int $page = 1): array
    {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM case_notes WHERE incident_id = ?');
        $stmt->execute([$incidentId]);
        $total = (int)$stmt->fetchColumn();
        $pages = max(1, (int)ceil($total / 25));
        $page = max(1, min($page, $pages));
        $stmt = $this->pdo->prepare('SELECT n.id, n.note_text, n.author_id, n.created_at, u.username AS author
            FROM case_notes n JOIN users u ON u.id = n.author_id WHERE n.incident_id = ?
            ORDER BY n.created_at DESC, n.id DESC LIMIT 25 OFFSET ?');
        $stmt->bindValue(1, $incidentId, PDO::PARAM_INT);
        $stmt->bindValue(2, ($page - 1) * 25, PDO::PARAM_INT);
        $stmt->execute();
        return ['notes'=>$stmt->fetchAll(PDO::FETCH_ASSOC), 'total'=>$total, 'page'=>$page, 'pages'=>$pages];
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
