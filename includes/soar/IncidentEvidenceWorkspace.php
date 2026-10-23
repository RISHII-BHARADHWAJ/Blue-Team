<?php
declare(strict_types=1);
require_once __DIR__.'/IncidentRepository.php';
require_once __DIR__.'/IncidentStateMachine.php';
require_once __DIR__.'/CaseNoteService.php';
require_once __DIR__.'/../siem/EventEvidenceRepository.php';

final class IncidentEvidenceConflict extends RuntimeException {}

/** Explicit case-evidence association; no risk recalculation or response execution. */
final class IncidentEvidenceWorkspace {
    public function __construct(private PDO $pdo) {}

    private function incident(int $id,bool $lock=false): array {
        $case=(new IncidentRepository($this->pdo))->find($id,$lock);
        if (!$case) throw new OutOfBoundsException('Incident not found.');
        if (!empty($case['is_simulated'])) throw new InvalidArgumentException('Simulated cases use the simulated walkthrough, not the real-evidence picker.');
        return $case;
    }

    public function view(int $id,array $input=[],int $page=1,?int $logId=null): array {
        $case=$this->incident($id);
        $filters=['kind'=>'observed'];
        foreach (['q','source_ip'] as $key) {
            $value=$input[$key]??'';
            if (!is_string($value)||strlen($value)>200) throw new InvalidArgumentException('Search fields must be text of at most 200 UTF-8 bytes.');
            $filters[$key]=trim($value);
        }
        $events=(new EventEvidenceRepository($this->pdo))->search($filters,$page,25);
        $ids=array_map('intval',array_column($events['rows'],'log_id'));
        $linked=[];
        if ($ids) {
            $stmt=$this->pdo->prepare('SELECT log_id FROM incident_alerts WHERE incident_id=? AND log_id IN ('.implode(',',array_fill(0,count($ids),'?')).')');
            $stmt->execute(array_merge([$id],$ids));$linked=array_map('intval',$stmt->fetchAll(PDO::FETCH_COLUMN));
        }
        foreach ($events['rows'] as &$row) $row['linked_to_case']=in_array((int)$row['log_id'],$linked,true);
        unset($row);
        $selected=null;
        if ($logId!==null) {
            $stmt=$this->pdo->prepare('SELECT e.id,e.log_id,e.source,e.submitted_by,e.is_simulated,e.event_timestamp,e.received_at,
                l.source_ip,l.severity,LEFT(l.message,500) AS message,CHAR_LENGTH(l.message)>500 AS message_truncated
                FROM event_evidence e JOIN logs l ON l.id=e.log_id WHERE e.log_id=?');
            $stmt->execute([$logId]);$selected=$stmt->fetch(PDO::FETCH_ASSOC);
            if (!$selected) throw new OutOfBoundsException('Preserved event evidence not found. Legacy logs are not eligible here.');
            if (!empty($selected['is_simulated'])) throw new InvalidArgumentException('Simulated evidence cannot be linked to a real case.');
            $stmt=$this->pdo->prepare('SELECT COUNT(*) AS cases,COALESCE(SUM(incident_id=?),0) AS linked_to_case FROM incident_alerts WHERE log_id=?');
            $stmt->execute([$id,$logId]);$links=$stmt->fetch(PDO::FETCH_ASSOC);
            $selected['linked_to_case']=(bool)$links['linked_to_case'];$selected['case_count']=(int)$links['cases'];
        }
        return ['incident'=>$case,'filters'=>$filters,'events'=>$events,'selected'=>$selected];
    }

    public function attach(int $id,int $logId,array $auth,string $reason): array {
        $reason=trim($reason);
        if ($id<1||$logId<1) throw new InvalidArgumentException('Select a valid case and event.');
        if ($reason===''||strlen($reason)>CaseNoteService::MAX_BYTES||!preg_match('//u',$reason)) throw new InvalidArgumentException('Provide a valid UTF-8 investigation reason of at most 10,000 bytes.');
        if (($auth['auth_method']??'')!=='session'||empty($auth['user_id'])) throw new DomainException('A named analyst session is required.');
        $own=!$this->pdo->inTransaction();$sp='case_evidence_'.bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction();else $this->pdo->exec("SAVEPOINT $sp");
        try {
            $stmt=$this->pdo->prepare('SELECT id,username,role FROM users WHERE id=? LOCK IN SHARE MODE');
            $stmt->execute([(int)$auth['user_id']]);$user=$stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user||!SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']),'attach_alerts')) throw new DomainException('A current Tier 2 or higher analyst account is required.');
            // Match the escalation workflow's evidence-before-case lock order.
            $stmt=$this->pdo->prepare('SELECT id,is_simulated FROM event_evidence WHERE log_id=? FOR UPDATE');
            $stmt->execute([$logId]);$event=$stmt->fetch(PDO::FETCH_ASSOC);
            if (!$event) throw new OutOfBoundsException('Preserved event evidence not found.');
            if (!empty($event['is_simulated'])) throw new InvalidArgumentException('Simulated evidence cannot be linked to a real case.');
            $case=$this->incident($id,true);
            $stmt=$this->pdo->prepare('SELECT id FROM incident_alerts WHERE incident_id=? AND log_id=? FOR UPDATE');
            $stmt->execute([$id,$logId]);$existing=$stmt->fetchColumn();
            if ($existing) {
                $result=['incident_id'=>$id,'log_id'=>$logId,'added'=>false];
            } else {
                if (!IncidentStateMachine::isActive($case['status'])) throw new IncidentEvidenceConflict('This case is no longer active. New evidence cannot be attached. Reload the case.');
                (new IncidentRepository($this->pdo))->attachAlert($id,$logId,'ANALYST_EVIDENCE_ATTACHMENT');
                (new IncidentTimeline($this->pdo))->addEvent($id,'ALERT_ADDED','ANALYST',$user['username'],
                    'Preserved event #'.$logId.' attached by an analyst',['log_id'=>$logId,'evidence_id'=>(int)$event['id'],'author_id'=>(int)$user['id']]);
                $note=(new CaseNoteService($this->pdo))->add($id,(int)$user['id'],$reason);
                $stmt=$this->pdo->prepare("INSERT INTO audit_log (analyst,ip_address,action,target,result,details,user_agent) VALUES (?,?,'attach_event_evidence',?,'success',?,?)");
                $stmt->execute([substr($user['username'],0,50),substr($_SERVER['REMOTE_ADDR']??'127.0.0.1',0,45),'incident:'.$id,
                    json_encode(['incident_id'=>$id,'log_id'=>$logId,'evidence_id'=>(int)$event['id'],'author_id'=>(int)$user['id'],'note_id'=>$note['id']],JSON_THROW_ON_ERROR),
                    substr($_SERVER['HTTP_USER_AGENT']??'ThreatPulse-CaseEvidence',0,500)]);
                $result=['incident_id'=>$id,'log_id'=>$logId,'added'=>true];
            }
            if ($own) $this->pdo->commit();else $this->pdo->exec("RELEASE SAVEPOINT $sp");
            return $result;
        } catch(Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();else {$this->pdo->exec("ROLLBACK TO SAVEPOINT $sp");$this->pdo->exec("RELEASE SAVEPOINT $sp");}
            }
            throw $e;
        }
    }
}
