<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/soar/Risk/RiskScoreCalculator.php';
function riskCheck(bool $ok, string $message): void { if (!$ok) throw new RuntimeException('FAIL: '.$message); echo "PASS: $message\n"; }
$calculator=new RiskScoreCalculator(); $now=1800000000;
$factor=function(string $name,array $alerts=[],array $iocs=[],array $incident=[])use($calculator,$now):RiskFactor{
    foreach($calculator->calculate($incident,$alerts,$iocs,[],$now)->factors as $f)if($f->name===$name)return $f;
    throw new RuntimeException('Missing factor');
};
try {
    foreach ([60=>5,300=>5,301=>3,1800=>3,1801=>1,7200=>1,7201=>0,86400=>0] as $age=>$expected) {
        riskCheck($factor('attack_recency',[['event_timestamp'=>gmdate('Y-m-d H:i:s',$now-$age)]])->contribution===$expected,"recency at $age seconds contributes $expected");
    }
    foreach ([[],[['event_timestamp'=>'invalid']],[['event_timestamp'=>gmdate('Y-m-d H:i:s',$now+3600)]]] as $alerts) {
        $f=$factor('attack_recency',$alerts);riskCheck($f->contribution===0 && $f->value==='UNKNOWN','missing, invalid or future-only timestamp adds no recency');
    }
    riskCheck($factor('attack_recency',[['timestamp'=>gmdate('Y-m-d H:i:s',$now-86400)],['event_timestamp'=>gmdate('Y-m-d H:i:s',$now+3600)]])->contribution===0,'future event does not make old evidence fresh');
    riskCheck($factor('attack_recency',[['event_timestamp'=>gmdate('c',$now-600)]])->contribution===3,'explicit UTC timestamp preserves its age');
    riskCheck($factor('alert_volume')->value==='0 alerts','empty case does not invent an attached alert');
    riskCheck($factor('alert_severity',[['severity'=>'WARNING']])->contribution===14,'legacy WARNING retains MEDIUM severity contribution');
    foreach ([[],[['source_ip'=>'8.8.8.8']],[['source_ip'=>'192.0.2.55','destination_ip'=>'10.0.0.1']],[['source_ip'=>'not-an-ip','destination_ip'=>'10.0.0.1']]] as $alerts) {
        riskCheck($factor('network_context',$alerts)->contribution===0,'unknown topology and documentation addresses add no exposure');
    }
    riskCheck($factor('network_context',[['source_ip'=>'8.8.8.8','destination_ip'=>'10.0.0.1']])->contribution===5,'reported public to private pair adds exposure');
    riskCheck($factor('network_context',[['source_ip'=>'10.0.0.2','destination_ip'=>'192.168.1.5']])->contribution===2,'reported private pair uses internal weight');
    riskCheck($factor('network_context',[['source_ip'=>'8.8.8.8'],['destination_ip'=>'10.0.0.1']])->contribution===0,'endpoints from different events cannot invent a pair');
    riskCheck($factor('ioc_reputation',[],[['threat_type'=>'some label','confidence_score'=>100]])->contribution===0,'free-text threat type is not a malicious assessment');
    riskCheck($factor('ioc_confidence',[],[['assessment'=>'MALICIOUS','confidence_score'=>20],['assessment'=>'BENIGN','confidence_score'=>100]])->contribution===1,'benign high confidence cannot boost malicious confidence');
    riskCheck($calculator->calculate([],[],[],[],$now)->policy_version==='v1.1','new calculations are policy-versioned');
} catch(Throwable $e) { fwrite(STDERR,$e->getMessage()."\n");exit(1); }
