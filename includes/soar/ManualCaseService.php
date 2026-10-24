<?php
declare(strict_types=1);
require_once __DIR__.'/IncidentManager.php';
require_once __DIR__.'/CaseNoteService.php';

final class ManualCaseConflict extends RuntimeException {}

/** Explicit analyst reports, with durable per-user submission identity. */
final class ManualCaseService {
    public function __construct(private PDO $pdo) {}

    public function actor(array $auth,bool $lock=false): array {
        if (($auth['auth_method'] ?? '') !== 'session' || empty($auth['user_id'])) throw new DomainException('A named Tier 2 or higher analyst session is required.');
        $stmt=$this->pdo->prepare('SELECT id,username,role FROM users WHERE id=?'.($lock?' LOCK IN SHARE MODE':''));
        $stmt->execute([(int)$auth['user_id']]);$user=$stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']),'create_incidents')) throw new DomainException('A current Tier 2 or higher account is required to report a case.');
        return $user;
    }

    public function available(): void {
        // Missing migration must be explicit; do not create a case without retry protection.
        $this->pdo->query('SELECT user_id,request_key,payload_hash,incident_id FROM manual_case_requests LIMIT 0');
    }

    public function create(array $auth,string $key,string $title,string $severity,string $report): array {
        $title=trim($title);$report=trim($report);
        if (!preg_match('/^[a-f0-9]{32}$/D',$key)) throw new InvalidArgumentException('Invalid submission key. Open a new intake form.');
        if ($title==='' || strlen($title)>255 || !preg_match('//u',$title)) throw new InvalidArgumentException('Provide a title of at most 255 valid UTF-8 bytes.');
        if ($report==='' || strlen($report)>CaseNoteService::MAX_BYTES || !preg_match('//u',$report)) throw new InvalidArgumentException('Provide a report of at most 10,000 valid UTF-8 bytes.');
        if (!in_array($severity,AlertSchema::SEVERITIES,true)) throw new InvalidArgumentException('Select a valid severity.');
        $hash=hash('sha256',json_encode([$title,$severity,$report],JSON_THROW_ON_ERROR));
        $own=!$this->pdo->inTransaction();$savepoint='intake_'.bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction();else $this->pdo->exec("SAVEPOINT $savepoint");
        try {
            $user=$this->actor($auth,true);
            $stmt=$this->pdo->prepare('INSERT INTO manual_case_requests (user_id,request_key,payload_hash) VALUES (?,?,?) ON DUPLICATE KEY UPDATE request_key=VALUES(request_key)');
            $stmt->execute([(int)$user['id'],$key,$hash]);
            $stmt=$this->pdo->prepare('SELECT id,payload_hash,incident_id FROM manual_case_requests WHERE user_id=? AND request_key=? FOR UPDATE');
            $stmt->execute([(int)$user['id'],$key]);$request=$stmt->fetch(PDO::FETCH_ASSOC);
            if (!hash_equals($request['payload_hash'],$hash)) throw new ManualCaseConflict('This submission was already used with different content. Return to the original submission or open a new intake form.');
            if ($request['incident_id']!==null) {
                $result=['created'=>false,'incident_id'=>(int)$request['incident_id']];
            } else {
                $case=(new IncidentManager($this->pdo))->createIncident([
                    'title'=>$title,'severity'=>$severity,'attack_category'=>'Manual report',
                    'description'=>"Analyst-reported case. No sensor evidence was attached at creation.\n\n".$report,
                ],null,null,$user['username'],'MANUAL_REPORT');
                $id=(int)$case['id'];
                $note=(new CaseNoteService($this->pdo))->add($id,(int)$user['id'],$report);
                $stmt=$this->pdo->prepare("INSERT INTO audit_log (analyst,ip_address,action,target,result,details,user_agent) VALUES (?,?,'create_manual_case',?,'success',?,?)");
                $stmt->execute([$user['username'],substr($_SERVER['REMOTE_ADDR']??'127.0.0.1',0,45),'incident:'.$id,
                    json_encode(['incident_id'=>$id,'author_id'=>(int)$user['id'],'note_id'=>$note['id'],'request_id'=>(int)$request['id'],'origin'=>'manual_report'],JSON_THROW_ON_ERROR),
                    substr($_SERVER['HTTP_USER_AGENT']??'ThreatPulse-ManualIntake',0,500)]);
                $stmt=$this->pdo->prepare('UPDATE manual_case_requests SET incident_id=? WHERE id=?');$stmt->execute([$id,$request['id']]);
                $result=['created'=>true,'incident_id'=>$id];
            }
            if ($own) $this->pdo->commit();else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
            return $result;
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();else {$this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint");$this->pdo->exec("RELEASE SAVEPOINT $savepoint");}
            }
            throw $e;
        }
    }
}
