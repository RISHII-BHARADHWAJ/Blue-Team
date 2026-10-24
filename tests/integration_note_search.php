<?php
require_once __DIR__.'/audit_history_fixtures.php';
require_once __DIR__.'/../includes/soar/CaseNoteService.php';
function nsCheck($ok,$msg){if(!$ok)throw new RuntimeException($msg);echo "PASS: $msg\n";}
$pdo->beginTransaction();
try{
$name='note-search-'.bin2hex(random_bytes(5));$uid=auditUser($pdo,$name,'user');$m=new IncidentManager($pdo);$case=$m->createIncident(['title'=>$name]);$other=$m->createIncident(['title'=>$name.' other']);$s=new CaseNoteService($pdo);
for($i=0;$i<27;$i++)$s->add((int)$case['id'],$uid,'needle '.$i);
$s->add((int)$other['id'],$uid,'needle other');$s->add((int)$case['id'],$uid,'literal 100%_!');
$a=$s->list((int)$case['id'],1,'needle');$b=$s->list((int)$case['id'],999,'needle');
nsCheck($a['total']===27 && count($a['notes'])===25 && count($b['notes'])===2 && $b['page']===2,'search spans pages and remains case scoped');
nsCheck(count(array_unique(array_column(array_merge($a['notes'],$b['notes']),'id')))===27,'stable pagination has no duplicates');
nsCheck($s->list((int)$case['id'],1,$name)['total']===28,'current author search');
nsCheck($s->list((int)$case['id'],1,'100%_!')['total']===1,'literal wildcards');
nsCheck($s->list((int)$case['id'],1,"' OR 1=1 --")['total']===0,'SQL remains data');
foreach([[],str_repeat('x',201),"\xff"] as $bad){$invalid=false;try{CaseNoteService::searchText($bad);}catch(InvalidArgumentException $e){$invalid=true;}nsCheck($invalid,'invalid query rejected');}
nsCheck($pdo->inTransaction(),'caller transaction preserved');$pdo->rollBack();
nsCheck($s->list((int)$case['id'])['total']===0 && !$pdo->inTransaction(),'empty owned snapshot closed');
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage());exit(1);}
