<?php
// Synthetic presentation fixtures: disposable CI database only.
require_once __DIR__.'/audit_history_fixtures.php';
require_once __DIR__.'/../includes/soar/CaseNoteService.php';
require_once __DIR__.'/../includes/siem/EventEvidenceRepository.php';
$uid=auditUser($pdo,'Morgan Chen','admin');
$manager=new IncidentManager($pdo);$cases=[];
foreach([['Unusual authentication activity','HIGH','Identity'],['Outbound connection review','MEDIUM','Network'],['Privilege change investigation','CRITICAL','Access'],['Web request anomaly','LOW','Application']] as [$title,$severity,$category]){
 $case=$manager->createIncident(['title'=>$title,'severity'=>$severity,'attack_category'=>$category,'description'=>'Synthetic CI presentation fixture. Review the reported activity, establish scope, and document the investigation.']);$cases[]=(int)$case['id'];
 (new CaseNoteService($pdo))->add((int)$case['id'],$uid,'Initial review completed. Compare the reported activity with the expected access pattern and confirm ownership before taking further action.');
}
$messages=['Repeated authentication failure for service account','Outbound TLS connection to an unrecognized destination','Elevated access requested outside the usual window','Web request matched an application detection rule'];
for($i=0;$i<12;$i++){
 $severity=['HIGH','MEDIUM','INFO','LOW'][$i%4];$source=['identity-gateway','edge-firewall','access-monitor','web-gateway'][$i%4];$ip='192.0.2.'.(20+$i);
 $alert=new AlertSchema(message:$messages[$i%4],severity:$severity,source:$source,source_type:'sensor');
 $pdo->prepare('INSERT INTO logs (source_ip,severity,category,message) VALUES (?,?,?,?)')->execute([$ip,$severity==='MEDIUM'?'WARNING':$severity,'Other',$alert->message]);$log=(int)$pdo->lastInsertId();
 (new EventEvidenceRepository($pdo))->append($log,$alert->toArray(),['message'=>$alert->message],hash('sha256','ui-'.$i),'ci-visual-fixture',null);
 (new IncidentRepository($pdo))->attachAlert($cases[$i%4],$log,'CI_VISUAL_FIXTURE');
}
session_name('CYBERTECH_SECURE_SESSION');session_id('ci-visual-acceptance');session_start();$_SESSION=['user_id'=>$uid,'username'=>'Morgan Chen','analyst'=>'Morgan Chen','role'=>'admin','csrf_token'=>'ci-visual-token'];session_write_close();
echo json_encode(['case_id'=>$cases[0],'session'=>'ci-visual-acceptance']);
