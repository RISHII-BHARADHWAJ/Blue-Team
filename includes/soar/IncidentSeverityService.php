<?php
declare(strict_types=1);
require_once __DIR__.'/SoarAuth.php';
require_once __DIR__.'/IncidentTimeline.php';

final class IncidentSeverityConflict extends RuntimeException {}

/** Named lead/admin severity triage, with atomic attribution and stale-value protection. */
final class IncidentSeverityService {
    public const PRIORITIES = ['CRITICAL'=>'P1','HIGH'=>'P2','MEDIUM'=>'P3','LOW'=>'P4','INFO'=>'P4'];
    public function __construct(private PDO $pdo) {}

    public function change(array $auth, int $id, string $severity, string $expectedSeverity, string $expectedPriority, string $reason): array {
        if (($auth['auth_method'] ?? '') !== 'session' || empty($auth['user_id'])) throw new DomainException('A named lead or administrator account is required.');
        if ($id < 1 || !isset(self::PRIORITIES[$severity],self::PRIORITIES[$expectedSeverity]) || !in_array($expectedPriority,['P1','P2','P3','P4'],true)) throw new InvalidArgumentException('Choose valid severity and expected case values.');
        $reason = trim($reason);
        if ($reason === '' || strlen($reason)>2000 || !preg_match('//u',$reason)) throw new InvalidArgumentException('Provide a reason of at most 2,000 valid UTF-8 bytes.');
        $own = !$this->pdo->inTransaction(); $savepoint = 'severity_'.bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $savepoint");
        try {
            $stmt = $this->pdo->prepare('SELECT id,incident_number,severity,priority,status,is_simulated,updated_at FROM incidents WHERE id=? FOR UPDATE');
            $stmt->execute([$id]); $case = $stmt->fetch(PDO::FETCH_ASSOC);
            // A locking read checks the current role, even inside an older caller snapshot.
            $stmt = $this->pdo->prepare('SELECT username,role FROM users WHERE id=? LOCK IN SHARE MODE');
            $stmt->execute([(int)$auth['user_id']]); $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']),'change_severity')) throw new DomainException('Only current lead or administrator accounts may change severity.');
            if (!$case) throw new OutOfBoundsException('Incident not found.');
            if ($case['status'] === 'CLOSED') throw new IncidentSeverityConflict('Closed cases cannot change severity.');
            $changed = $case['severity'] !== $severity;
            $noteId = null;
            if ($changed) {
                if ($case['severity'] !== $expectedSeverity || $case['priority'] !== $expectedPriority) throw new IncidentSeverityConflict('Case severity or priority changed since this page was loaded. Reload the case before submitting.');
                $priority = self::PRIORITIES[$severity];
                $stmt = $this->pdo->prepare('UPDATE incidents SET severity=?,priority=?,updated_at=NOW() WHERE id=?');
                $stmt->execute([$severity,$priority,$id]);
                $summary = "Severity changed from {$case['severity']} to $severity; priority {$case['priority']} to $priority";
                $stmt = $this->pdo->prepare('INSERT INTO case_notes (incident_id,author_id,note_text) VALUES (?,?,?)');
                $stmt->execute([$id,(int)$auth['user_id'],$summary."\nReason: ".$reason]); $noteId = (int)$this->pdo->lastInsertId();
                $details = ['incident_id'=>$id,'author_id'=>(int)$auth['user_id'],'old_severity'=>$case['severity'],'new_severity'=>$severity,'old_priority'=>$case['priority'],'new_priority'=>$priority,'note_id'=>$noteId];
                (new IncidentTimeline($this->pdo))->addEvent($id,'SEVERITY_CHANGE','ANALYST',$user['username'],$summary." (note #$noteId)",$details);
                $stmt = $this->pdo->prepare("INSERT INTO audit_log (analyst,ip_address,action,target,result,details,user_agent) VALUES (?,?,'change_incident_severity',?,'success',?,?)");
                $stmt->execute([$user['username'],substr($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',0,45),'incident:'.$id,json_encode($details,JSON_THROW_ON_ERROR),substr($_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-Severity',0,500)]);
                // Use a current read so borrowed snapshots cannot return stale case values.
                $stmt = $this->pdo->prepare('SELECT id,incident_number,severity,priority,status,is_simulated,updated_at FROM incidents WHERE id=? FOR UPDATE');
                $stmt->execute([$id]); $case = $stmt->fetch(PDO::FETCH_ASSOC);
            }
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
            return ['changed'=>$changed,'incident'=>$case,'note_id'=>$noteId];
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint"); $this->pdo->exec("RELEASE SAVEPOINT $savepoint"); }
            }
            throw $e;
        }
    }
}
