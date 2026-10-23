<?php
declare(strict_types=1);
require_once __DIR__.'/IncidentManager.php';
require_once __DIR__.'/CaseNoteService.php';

/** Explicit analyst escalation of preserved real evidence. Never executes response actions. */
final class EventEscalationService {
    public function __construct(private PDO $pdo) {}

    public function actor(array $auth): array {
        if (($auth['auth_method'] ?? '') !== 'session' || empty($auth['user_id'])) {
            throw new DomainException('A named analyst session is required.');
        }
        $stmt=$this->pdo->prepare('SELECT id,username,role FROM users WHERE id=?');
        $stmt->execute([(int)$auth['user_id']]);$user=$stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']),'manual_escalate')) {
            throw new DomainException('A current Tier 2 or higher analyst account is required.');
        }
        return $user;
    }

    public function preview(int $logId,array $auth): array {
        $this->actor($auth);
        return $this->evidence($logId);
    }

    private function evidence(int $logId): array {
        $stmt=$this->pdo->prepare('SELECT e.id,e.log_id,e.source,e.source_type,e.submitted_by,e.is_simulated,
            e.received_at,e.event_timestamp,e.canonical_json,LEFT(l.message,500) AS message,
            CHAR_LENGTH(l.message)>500 AS message_truncated FROM event_evidence e JOIN logs l ON l.id=e.log_id WHERE e.log_id=?');
        $stmt->execute([$logId]);$row=$stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) throw new OutOfBoundsException('Preserved event evidence was not found. Legacy logs cannot be escalated here.');
        if ((int)$row['is_simulated'] !== 0) throw new InvalidArgumentException('Simulated evidence cannot create a real incident. Use the simulated walkthrough.');
        $canonical=json_decode($row['canonical_json'],true,512,JSON_THROW_ON_ERROR);
        if (!is_array($canonical) || !empty($canonical['is_simulated']) || !in_array($canonical['severity']??null,AlertSchema::SEVERITIES,true)) {
            throw new UnexpectedValueException('Stored event classification is inconsistent.');
        }
        $row['canonical']=$canonical;unset($row['canonical_json']);
        $stmt=$this->pdo->prepare('SELECT i.id,i.incident_number,i.status,i.is_simulated FROM incident_alerts ia JOIN incidents i ON i.id=ia.incident_id WHERE ia.log_id=? ORDER BY i.id ASC');
        $stmt->execute([$logId]);$row['incidents']=$stmt->fetchAll(PDO::FETCH_ASSOC);
        return $row;
    }

    public function escalate(int $logId,array $auth,string $title,string $reason): array {
        $title=trim($title);$reason=trim($reason);
        if ($title==='' || strlen($title)>255 || !preg_match('//u',$title)) throw new InvalidArgumentException('Provide a valid UTF-8 case title of at most 255 bytes.');
        if ($reason==='' || strlen($reason)>CaseNoteService::MAX_BYTES || !preg_match('//u',$reason)) throw new InvalidArgumentException('Provide an investigation reason of at most 10,000 UTF-8 bytes.');
        $own=!$this->pdo->inTransaction();$savepoint='escalate_'.bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction();else $this->pdo->exec("SAVEPOINT $savepoint");
        try {
            $user=$this->actor($auth);
            // Serialize this workflow by immutable evidence row. Locking reads see committed retries.
            $stmt=$this->pdo->prepare('SELECT log_id FROM event_evidence WHERE log_id=? FOR UPDATE');
            $stmt->execute([$logId]);
            if (!$stmt->fetchColumn()) throw new OutOfBoundsException('Preserved event evidence was not found.');
            $event=$this->evidence($logId);
            // Use a current locking read even when the caller established an older snapshot.
            $stmt=$this->pdo->prepare('SELECT i.id,i.is_simulated FROM incident_alerts ia JOIN incidents i ON i.id=ia.incident_id WHERE ia.log_id=? ORDER BY i.id ASC FOR UPDATE');
            $stmt->execute([$logId]);$linked=$stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($linked) {
                foreach ($linked as $case) if ((int)$case['is_simulated']!==0) throw new DomainException('Evidence has an inconsistent simulated case link.');
                $result=['incident_id'=>(int)$linked[0]['id'],'created'=>false];
            } else {
                $alert=AlertSchema::fromArray($event['canonical']);
                $case=(new IncidentManager($this->pdo))->createIncident([
                    'title'=>$title,'description'=>'Analyst escalation from preserved event log #'.$logId.'. See the initial investigation note for the rationale.',
                    'severity'=>$alert->severity,'attack_category'=>$alert->category,
                ],$alert,$logId,$user['username'],'ANALYST_EVIDENCE_ESCALATION');
                $id=(int)$case['id'];
                $note=(new CaseNoteService($this->pdo))->add($id,(int)$user['id'],$reason);
                $stmt=$this->pdo->prepare("INSERT INTO audit_log (analyst,ip_address,action,target,result,details,user_agent) VALUES (?,?,'escalate_event',?,'success',?,?)");
                $stmt->execute([substr($user['username'],0,50),substr($_SERVER['REMOTE_ADDR']??'127.0.0.1',0,45),'incident:'.$id,
                    json_encode(['incident_id'=>$id,'log_id'=>$logId,'evidence_id'=>(int)$event['id'],'author_id'=>(int)$user['id'],'note_id'=>$note['id']],JSON_THROW_ON_ERROR),
                    substr($_SERVER['HTTP_USER_AGENT']??'ThreatPulse-EventEscalation',0,500)]);
                $result=['incident_id'=>$id,'created'=>true];
            }
            if ($own) $this->pdo->commit();else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
            return $result;
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint");$this->pdo->exec("RELEASE SAVEPOINT $savepoint"); }
            }
            throw $e;
        }
    }
}
