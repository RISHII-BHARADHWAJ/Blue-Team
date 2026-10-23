<?php
/** Interleave a committed note between report queries; fixture stays in disposable CI. */
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
require_once __DIR__.'/../includes/soar/IncidentReportService.php';
class InterleavingReportPdo extends PDO {
    public ?Closure $duringRead=null;
    public function prepare(string $query,array $options=[]):PDOStatement|false {
        if($this->duringRead && str_contains($query,'SELECT COUNT(*) FROM case_notes')){
            $callback=$this->duringRead;$this->duringRead=null;$callback();
        }
        return parent::prepare($query,$options);
    }
}
try{
    $name='report-race-'.bin2hex(random_bytes(6));
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash','user']);$uid=(int)$pdo->lastInsertId();
    $case=(new IncidentManager($pdo))->createIncident(['title'=>$name]);$id=(int)$case['id'];
    $reader=new InterleavingReportPdo('mysql:host='.getenv('DB_HOST').';dbname='.getenv('DB_NAME').';charset=utf8mb4',getenv('DB_USER'),getenv('DB_PASS'),[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    $reader->duringRead=function()use($pdo,$id,$uid):void{$pdo->prepare('INSERT INTO case_notes (incident_id,author_id,note_text) VALUES (?,?,?)')->execute([$id,$uid,'Committed during report']);};
    $service=new IncidentReportService($reader);$first=$service->build($id);$second=$service->build($id);
    if($first['sections']['notes']['total']!==0 || $first['sections']['notes']['included']!==0 || $second['sections']['notes']['total']!==1 || $reader->inTransaction())throw new RuntimeException('Report mixed snapshots or left a transaction open');
    try{$service->build(2147483647);throw new RuntimeException('Missing case accepted');}catch(OutOfBoundsException $e){}
    if($reader->inTransaction())throw new RuntimeException('Failed report left transaction open');
    echo "PASS: report counts and rows share a consistent snapshot; next report sees concurrent committed note; owned transactions close.\n";
}catch(Throwable $e){fwrite(STDERR,$e->getMessage()."\n");exit(1);}
