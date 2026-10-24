<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/IncidentReportService.php';
$auth=SoarAuth::getContext($pdo);
$format=$_GET['format']??'html';
header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');
if($auth['actor']==='anonymous'){
    if($format==='json'){header('Content-Type: application/json; charset=utf-8');http_response_code(401);echo '{"error":"Authentication required."}';}
    else header('Location: login.php');
    exit;
}
if(!SoarAuth::hasPermission($auth['tier'],'view_incidents')){http_response_code(403);exit('Not authorized.');}
if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET');http_response_code(405);exit;}
require_once __DIR__.'/includes/security.php';
function reportEscape(mixed $value):string{return htmlspecialchars((string)($value??'—'),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function reportCell(mixed $value):string{return is_bool($value)?($value?'Yes':'No'):reportEscape($value);}
$id=filter_var($_GET['id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
$error=null;$report=null;
try{
    if(!$id||!is_string($format)||!in_array($format,['html','json'],true))throw new InvalidArgumentException('Select a valid incident and report format.');
    $report=(new IncidentReportService($pdo))->build($id);
}catch(InvalidArgumentException $e){http_response_code(422);$error=$e->getMessage();}
catch(OutOfBoundsException $e){http_response_code(404);$error=$e->getMessage();}
catch(Throwable $e){error_log('Incident report failed: '.$e->getMessage());http_response_code(500);$error='The report could not be generated. Check database health and required migrations.';}
if($format==='json'){
    header('Content-Type: application/json; charset=utf-8');
    if($error){echo json_encode(['error'=>$error],JSON_THROW_ON_ERROR);exit;}
    header('Content-Disposition: attachment; filename="threatpulse-incident-'.(int)$id.'-report.json"');
    echo IncidentReportService::json($report);exit;
}
$sectionDefinitions=[
    'alerts'=>['title'=>'Linked alerts and event evidence','description'=>'Evidence IDs and recorded payload hashes reference preserved submissions; payload bytes are not included. A missing evidence ID denotes a legacy log without preserved event evidence.','columns'=>['log_id'=>'Log','source_ip'=>'Source IP','severity'=>'Severity','category'=>'Category','message'=>'Summary','event_timestamp'=>'Event time','evidence_id'=>'Evidence','source'=>'Sensor source','payload_sha256'=>'Recorded SHA-256','evidence_is_simulated'=>'Simulation flag']],
    'notes'=>['title'=>'Analyst notes','description'=>'Pinned notes appear first. Included text may contain sensitive case information.','columns'=>['id'=>'Note','author'=>'Author','is_pinned'=>'Pinned','note_text'=>'Text','created_at'=>'Created','updated_at'=>'Updated']],
    'indicators'=>['title'=>'Linked indicators','description'=>'Roles are inferred case context. This section does not assert a current provider verdict.','columns'=>['id'=>'IOC','ioc_type'=>'Type','ioc_value'=>'Indicator','role'=>'Case role','source_feed'=>'Registry source','discovered_at'=>'Linked']],
    'evidence'=>['title'=>'Evidence artifact references','description'=>'Recorded hashes are references, not a new verification of artifact contents. Artifact files and content are excluded.','columns'=>['id'=>'Artifact','evidence_type'=>'Type','title'=>'Title','data_hash'=>'Recorded hash','collector'=>'Collector','collected_at'=>'Collected']],
    'playbook_runs'=>['title'=>'Playbook runs','description'=>'COMPLETED + DRY_RUN means a completed preview. CURRENT_CATALOG names may differ from the name when an older run started. UNKNOWN mode is not inferred to be live execution.','columns'=>['id'=>'Run','playbook_name'=>'Playbook','name_source'=>'Name source','playbook_version'=>'Version','mode'=>'Mode','status'=>'Stored status','analyst'=>'Analyst','started_at'=>'Started','completed_at'=>'Completed']],
    'approvals'=>['title'=>'Approval requests','description'=>'EXPIRED_BY_TIME is a read-only interpretation of a pending request past its expiry. Report generation never updates approval status.','columns'=>['id'=>'Approval','playbook_run_id'=>'Run','action_name'=>'Action','required_tier'=>'Authority','stored_status'=>'Stored status','effective_status'=>'At report time','reviewer'=>'Reviewer','expires_at'=>'Expires','decided_at'=>'Decided']],
    'response_actions'=>['title'=>'Recorded response actions','description'=>'These are database records, not independent verification of containment. Output logs and action payloads are excluded.','columns'=>['id'=>'Action','playbook_run_id'=>'Run','action_type'=>'Type','target_entity'=>'Target','status'=>'Stored status','dispatched_at'=>'Dispatched','executed_at'=>'Executed','is_rolled_back'=>'Rolled back']],
    'timeline'=>['title'=>'Recent case timeline','description'=>'Newest milestones first. Structured details are excluded; inspect the case for the full timeline.','columns'=>['id'=>'Event','event_type'=>'Type','actor_name'=>'Actor','summary'=>'Summary','created_at'=>'Time']],
];
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Incident handoff report · ThreatPulse</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0a1422;color:#e4edf7;font:14px/1.55 system-ui,sans-serif}main{max-width:1320px;margin:auto;padding:28px 24px 60px}a{color:#76dfd2}nav,.actions,.report-top{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.report-top{justify-content:space-between;margin-top:24px}h1{font-size:32px;line-height:1.2;margin:8px 0}h2{font-size:21px}section{background:#122033;border:1px solid #2a425e;border-radius:12px;margin:20px 0;padding:22px}.muted,small{color:#a9bed3}.notice{padding:12px 16px;border-left:4px solid #ffd083;background:#302c23;color:#ffe1a3}.error{color:#ffb19c}.pill{display:inline-block;padding:4px 9px;border:1px solid #7094aa;border-radius:5px;font-weight:700}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px}.metrics strong{font-size:21px;display:block}small{display:block}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #2a425e;vertical-align:top;overflow-wrap:anywhere;min-width:70px}th{color:#a9bed3}td{max-width:300px;white-space:pre-wrap}button{font:inherit;font-weight:700;padding:11px 16px;border:0;border-radius:6px;background:#73dfd0;color:#092129;cursor:pointer}button.secondary{background:#29435c;color:#e4edf7}pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}.section-nav{margin:20px 0;gap:12px}.section-nav a{font-size:13px}.metadata{font-size:12px;overflow-wrap:anywhere}:focus-visible{outline:3px solid #ffd083;outline-offset:3px}.screen-only{display:flex}.text-warning{display:block;color:#ffd083;font-weight:700}
@media print{ :root{color-scheme:light}body{background:white;color:#111;font-size:10pt}main{max-width:none;padding:0}.screen-only,.section-nav{display:none!important}section{background:white;border:1px solid #bbb;border-radius:0;padding:12px;margin:12px 0}a,.muted,small,th{color:#333}.notice{background:#fff8e5;color:#111;border-color:#886000}.pill{border-color:#333}h1{font-size:24pt}h2{font-size:15pt;break-after:avoid}.scroll{overflow:visible}table{font-size:8pt;table-layout:fixed}th,td{padding:5px;min-width:0;max-width:none;border-color:#ccc}thead{display:table-header-group}tr{break-inside:avoid}.text-warning{color:#7d3e00}.metrics{grid-template-columns:repeat(4,1fr)}.metrics strong{font-size:13pt}@page{size:A4 landscape;margin:12mm}
</style><?php require_once __DIR__.'/includes/ui/shell.php'; tpHead(''); ?>
</head><body class="tp-app tp-page-cases"><?php tpShell('cases',''); ?><main>
<nav class="screen-only"><a href="soc.php">SOC overview</a><a href="incidents.php">Incident queue</a><?php if($id): ?><a href="incidents.php?id=<?= (int)$id ?>#details">Back to case</a><?php endif; ?></nav>
<?php if($error): ?><h1>Report unavailable</h1><p class="error" role="alert"><?= reportEscape($error) ?></p>
<?php else: $case=$report['incident'];$risk=$report['latest_risk_assessment']; ?>
<div class="report-top"><div><span class="pill"><?= reportEscape($report['simulation_label']) ?></span><p class="muted"><?= reportEscape($case['incident_number']) ?> / Analyst handoff</p><h1><?= reportEscape($case['title']) ?></h1></div><div class="actions screen-only"><button type="button" id="download-report" data-incident-id="<?= (int)$id ?>">Download this snapshot (JSON)</button><button type="button" id="print-report" class="secondary">Print / save PDF</button><noscript><a href="incident-report.php?id=<?= (int)$id ?>&amp;format=json">Generate a new JSON snapshot</a></noscript></div></div>
<p class="metadata">Generated <?= reportEscape($report['generated_at_utc']) ?> · <?= reportEscape($report['schema_version']) ?><br><?= reportEscape($report['record_time_basis']) ?></p>
<?php if($report['partial']): ?><p class="notice"><strong>PARTIAL REPORT:</strong> one or more sections or text fields exceed the report limits. Included and total counts are shown below. Use the case workspaces to inspect omitted records.</p><?php endif; ?>
<p class="muted">This is a handoff summary of saved records. It includes analyst notes and alert summaries; review before sharing. The JSON button downloads this displayed snapshot. Reloading or requesting a new report can produce different data.</p>
<nav class="section-nav screen-only"><?php foreach($sectionDefinitions as $key=>$definition): ?><a href="#<?= $key ?>"><?= reportEscape($definition['title']) ?> (<?= (int)$report['sections'][$key]['total'] ?>)</a><?php endforeach; ?></nav>
<section><h2>Case state</h2><div class="metrics"><?php foreach(['status'=>'Status','severity'=>'Severity','priority'=>'Priority','assigned_analyst'=>'Assigned analyst','lead_analyst_name'=>'Lead analyst','attack_category'=>'Category','created_at'=>'Created','updated_at'=>'Updated'] as $key=>$label): ?><div><small><?= $label ?></small><strong><?= reportEscape($case[$key]) ?></strong></div><?php endforeach; ?></div>
<?php if($case['description']!==null && $case['description']!==''): ?><h3>Description</h3><pre><?= reportEscape($case['description']) ?></pre><?php endif; ?><?php if($case['description_truncated']): ?><p class="text-warning">Description truncated at 10,000 characters.</p><?php endif; ?>
<p class="muted">Stored status does not verify external containment. Resolved: <?= reportEscape($case['resolved_at']) ?> · Closed: <?= reportEscape($case['closed_at']) ?></p></section>
<section><h2>Latest saved risk assessment</h2><?php if($risk): ?><div class="metrics"><div><small>Assessment</small><strong>#<?= (int)$risk['id'] ?></strong></div><div><small>Score / priority at calculation</small><strong><?= (int)$risk['score'] ?> / <?= reportEscape($risk['priority']) ?></strong></div><div><small>Evidence confidence</small><strong><?= reportEscape($risk['confidence']) ?></strong></div><div><small>Policy</small><strong><?= reportEscape($risk['policy_version']) ?></strong></div></div><p>Calculated <?= reportEscape($risk['calculated_at']) ?> by <?= reportEscape($risk['calculated_by']) ?>. Current case priority: <?= reportEscape($case['priority']) ?>.</p><?php else: ?><p>No saved risk assessment. An uncalculated score is not evidence of low risk.</p><?php endif; ?><p class="muted">Report generation does not recalculate risk. <a class="screen-only" href="incident-risk.php?id=<?= (int)$id ?>">Inspect the risk workspace</a></p></section>
<?php foreach($sectionDefinitions as $key=>$definition): $section=$report['sections'][$key]; ?><section id="<?= $key ?>"><h2><?= reportEscape($definition['title']) ?></h2><p class="muted"><?= reportEscape($definition['description']) ?></p><p><strong><?= (int)$section['included'] ?> of <?= (int)$section['total'] ?> records</strong> · <?= reportEscape($section['order']) ?><?php if($section['truncated']): ?> · <span class="text-warning">SECTION TRUNCATED at <?= (int)$section['limit'] ?> records</span><?php endif; ?></p>
<?php if($section['text_truncated_count']): ?><p class="notice"><?= (int)$section['text_truncated_count'] ?> included text field(s) truncated at 10,000 characters.</p><?php endif; ?>
<?php if(!$section['rows']): ?><p class="muted">No saved records in this section.</p><?php else: ?><div class="scroll"><table><thead><tr><?php foreach($definition['columns'] as $label): ?><th scope="col"><?= reportEscape($label) ?></th><?php endforeach; ?></tr></thead><tbody><?php foreach($section['rows'] as $row): ?><tr><?php foreach($definition['columns'] as $field=>$label): ?><td><?= reportCell($row[$field]) ?><?php if(in_array($field,['message','note_text'],true)&&!empty($row['text_truncated'])): ?><small class="text-warning">TEXT TRUNCATED</small><?php endif; ?></td><?php endforeach; ?></tr><?php endforeach; ?></tbody></table></div><?php endif; ?></section><?php endforeach; ?>
<section><h2>Scope and limitations</h2><ul><?php foreach($report['limitations'] as $limitation): ?><li><?= reportEscape($limitation) ?></li><?php endforeach; ?></ul></section>
<script type="application/json" id="report-snapshot"><?= str_replace('<','\u003C',IncidentReportService::json($report)) ?></script>
<script>
document.getElementById('print-report').addEventListener('click',()=>window.print());
document.getElementById('download-report').addEventListener('click',event=>{
 const report=JSON.parse(document.getElementById('report-snapshot').textContent);
 const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)+'\n'],{type:'application/json;charset=utf-8'}));
 const link=document.createElement('a');link.href=url;link.download='threatpulse-incident-'+event.currentTarget.dataset.incidentId+'-report.json';
 document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
</script>
<?php endif; ?></main></body></html>
