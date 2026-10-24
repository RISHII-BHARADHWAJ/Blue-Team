<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/SoarCsrf.php';
require_once __DIR__.'/includes/soar/playbooks/PlaybookWorkspace.php';
$auth=SoarAuth::getContext($pdo);
if($auth['actor']==='anonymous'){header('Location: login.php');exit;}
require_once __DIR__.'/includes/security.php';
header('Cache-Control: no-store');header('X-Frame-Options: DENY');
function playbookEscape(mixed $v):string{return htmlspecialchars((string)($v??''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function playbookUrl(array $p):string{return 'incident-playbooks.php?'.http_build_query(array_filter($p,fn($v)=>$v!==null));}
function playbookId(mixed $v):int|false{return filter_var($v,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);}
$canPreview=$auth['auth_method']==='session'&&!empty($auth['user_id']);
$service=new PlaybookWorkspace($pdo);$error=null;$data=null;
$id=playbookId($_POST['id']??$_GET['id']??null);
$selectedId=isset($_POST['playbook_id'])||isset($_GET['playbook_id'])?playbookId($_POST['playbook_id']??$_GET['playbook_id']):null;
$runId=isset($_GET['run_id'])?playbookId($_GET['run_id']):null;
$page=playbookId($_GET['page']??1)?:1;$catalogPage=playbookId($_GET['catalog_page']??1)?:1;
$requestKey=is_string($_POST['request_key']??null)&&preg_match('/^[a-f0-9]{32}$/D',$_POST['request_key'])?$_POST['request_key']:bin2hex(random_bytes(16));
try{
 if($_SERVER['REQUEST_METHOD']==='POST'){
  if(!$canPreview){http_response_code(403);exit('Sign in with a named user account to preview.');}
  SoarCsrf::enforce($auth);
  foreach(array_keys($_POST) as $field)if(!in_array($field,['id','playbook_id','version','request_key','csrf_token'],true))throw new InvalidArgumentException('Only the selected playbook and preview request fields may be submitted.');
  $version=playbookId($_POST['version']??null);
  if(!$id||!$selectedId||!$version||!is_string($_POST['request_key']??null))throw new InvalidArgumentException('A valid incident, playbook, version and request key are required.');
  $run=$service->preview($id,$selectedId,$version,(int)$auth['user_id'],$_POST['request_key']);
  header('Location: '.playbookUrl(['id'=>$id,'run_id'=>$run['id']]),true,303);exit;
 }
 if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET, POST');http_response_code(405);exit;}
 if(!$id||$selectedId===false||$runId===false)throw new InvalidArgumentException('Select a valid incident, playbook and run.');
 $data=$service->read($id,$page,$runId,$selectedId,$catalogPage);
}catch(DomainException $e){http_response_code(403);$error=$e->getMessage();}
catch(OutOfBoundsException $e){http_response_code(404);$error=$e->getMessage();}
catch(UnexpectedValueException $e){http_response_code(409);$error=$e->getMessage();}
catch(InvalidArgumentException $e){http_response_code(422);$error=$e->getMessage();}
catch(Throwable $e){error_log('Playbook workspace failed: '.$e->getMessage());http_response_code(500);$error='Could not complete the request. Check run history before retrying the same submission.';}
$csrf=$canPreview?generateCSRFToken():'';
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Incident playbooks · ThreatPulse</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0a1422;color:#e4edf7;font:15px/1.6 system-ui,sans-serif}main{max-width:1160px;margin:auto;padding:28px 22px 60px}nav,.pager{display:flex;gap:24px;flex-wrap:wrap;justify-content:space-between}nav{justify-content:flex-start}a{color:#76dfd2}h1{font-size:32px;line-height:1.2}h2{font-size:21px}h3{font-size:17px}section{background:#122033;border:1px solid #2a425e;border-radius:12px;margin:22px 0;padding:22px}.muted,small{color:#a9bed3}.notice{color:#ffd083}.error{color:#ffb19c}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.card,.step{border:1px solid #2a425e;border-radius:8px;padding:16px;margin:12px 0}.card h3{margin-top:0}button{background:#73dfd0;color:#092129;border:0;border-radius:7px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:12px 10px;border-bottom:1px solid #2a425e;vertical-align:top}th{color:#a9bed3}td small{display:block}.scroll{overflow:auto}.pill{border:1px solid #42617d;padding:3px 8px;border-radius:5px;display:inline-block}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}summary{cursor:pointer;color:#a9bed3}.pager{padding-top:16px}.status{font-size:20px;font-weight:700}
</style><?php require_once __DIR__.'/includes/ui/shell.php'; tpHead(''); ?>
</head><body class="tp-app tp-page-cases"><?php tpShell('cases',''); ?><main>
<nav><a href="soc.php">SOC overview</a><a href="incidents.php">Incident queue</a><a href="control_plane/index.php">Approval control plane</a></nav>
<h1>Playbooks and run history</h1>
<?php if($error):?><section class="error" role="alert"><?=playbookEscape($error)?><?php if($id):?><p><a href="incident-playbooks.php?id=<?=(int)$id?>">Reload this case's playbook workspace</a></p><?php endif;?></section><?php endif;?>
<?php if($data):$incident=$data['incident'];$run=$data['run'];$definition=$data['definition'];$pagination=$data['pagination'];$catalogPagination=$data['catalog_pagination'];?>
<p><a href="incidents.php?id=<?=(int)$id?>&amp;kind=<?=$incident['is_simulated']?'simulated':'observed'?>#details"><?=playbookEscape($incident['incident_number'])?> · <?=playbookEscape($incident['title'])?></a></p>
<?php if($incident['is_simulated']):?><p class="notice"><strong>SIMULATED TEST DATA</strong> — all playbook runs for this case are forced to dry-run.</p><?php endif;?>
<p class="muted">Inspect a playbook before previewing its steps against this case. Previews save run results and timeline entries. They do not query intelligence providers, send notifications, write case notes or forensic evidence, request approval, or contain a host.</p>
<?php if($run):$context=$run['execution_context'];$dry=($context['mode']??'')==='DRY_RUN';$snapshot=$context['definition_snapshot']??null;?>
<section id="run"><h2>Run #<?=(int)$run['id']?></h2><p class="status"><?=playbookEscape($run['status'])?> <span class="pill"><?=$dry?'DRY_RUN · preview only':playbookEscape($context['mode']??'Mode not recorded')?></span></p>
<p>Playbook #<?=(int)$run['playbook_id']?> · version <?=(int)$run['playbook_version']?> · <?=playbookEscape($run['started_at']??'Start not recorded')?> (server time)</p>
<?php if($dry):?><p class="muted">A completed preview means its simulated steps finished. It is not evidence that the actions were executed.</p><?php endif;?>
<?php if($run['error_message']):?><p class="error"><?=playbookEscape($run['error_message'])?></p><?php endif;?>
<?php if($data['approval']):?><p class="notice">This run has a pending approval. Review it in the <a href="control_plane/index.php">approval control plane</a>.</p><?php endif;?>
<?php foreach($data['results'] as $result):$output=json_decode($result['output']??'{}',true)?:[];?>
<div class="step"><strong>Step <?=(int)$result['step_order']?> · <?=playbookEscape(str_replace('_',' ',strtolower($result['action_type'])))?></strong><p><?=playbookEscape($result['status'])?> · attempt <?=(int)$result['attempt_number']?> · <?=$result['is_dry_run']?'Preview result':'Execution result'?></p><p><?=playbookEscape($output['message']??$result['error_message']??'No result message recorded.')?></p>
<?php if(!empty($output['data'])):?><details><summary>Result details</summary><pre><?=playbookEscape(json_encode($output['data'],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES))?></pre></details><?php endif;?></div>
<?php endforeach;?>
<?php if(!$data['results']):?><p class="muted">No step results recorded yet. Reload to check the current state.</p><?php endif;?>
<?php if($snapshot):?><details><summary>Definition saved with this preview: <?=playbookEscape($snapshot['playbook']['display_name']??'')?></summary><pre><?=playbookEscape(json_encode($snapshot,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES))?></pre></details><?php else:?><p class="muted">No definition snapshot was saved with this run. Its recorded step results are shown above; the active catalog below may have changed.</p><?php endif;?>
</section><?php endif;?>
<section><h2>Active playbooks</h2><p class="muted"><?=(int)$catalogPagination['total']?> active definitions · showing up to 10 per page. Choose one to inspect its current steps.</p><div class="cards">
<?php foreach($data['catalog'] as $playbook):?><article class="card"><h3><?=playbookEscape($playbook['display_name'])?></h3><p><?=playbookEscape($playbook['description']??'')?></p><p class="muted"><?=playbookEscape($playbook['category'])?> · version <?=(int)$playbook['version']?></p><a href="<?=playbookEscape(playbookUrl(['id'=>$id,'playbook_id'=>$playbook['id'],'catalog_page'=>$catalogPagination['page']]))?>#definition">Inspect steps</a></article><?php endforeach;?></div>
<?php if(!$data['catalog']):?><p>No active playbooks. Ask an administrator to add a validated definition.</p><?php endif;?>
<div class="pager"><span>Catalog page <?=(int)$catalogPagination['page']?> of <?=(int)$catalogPagination['pages']?></span><span><?php if($catalogPagination['page']>1):?><a href="<?=playbookEscape(playbookUrl(['id'=>$id,'catalog_page'=>$catalogPagination['page']-1]))?>">Previous</a><?php endif;?> <?php if($catalogPagination['page']<$catalogPagination['pages']):?><a href="<?=playbookEscape(playbookUrl(['id'=>$id,'catalog_page'=>$catalogPagination['page']+1]))?>">Next</a><?php endif;?></span></div></section>
<?php if($definition):?><section id="definition"><h2><?=playbookEscape($definition['display_name'])?></h2><p>Current version <?=(int)$definition['version']?>. This workspace starts previews only.</p>
<?php foreach($data['steps'] as $step):?><div class="step"><strong><?=(int)$step['step_order']?>. <?=playbookEscape($step['step_name'])?></strong><p><?=playbookEscape(str_replace('_',' ',strtolower($step['action_type'])))?></p><details><summary>Parameters and branches</summary><pre><?=playbookEscape($step['action_parameters']??'{}')?></pre><p>On success: <?=!empty($step['on_success_step'])?'step ID '.(int)$step['on_success_step']:'next step'?> · On failure: <?=!empty($step['on_failure_step'])?'step ID '.(int)$step['on_failure_step']:'stop run'?></p></details></div><?php endforeach;?>
<?php if(!$data['steps']):?><p class="notice">This definition has no steps and cannot be previewed.</p><?php elseif($canPreview):?><form method="post" action="incident-playbooks.php"><input type="hidden" name="id" value="<?=(int)$id?>"><input type="hidden" name="playbook_id" value="<?=(int)$definition['id']?>"><input type="hidden" name="version" value="<?=(int)$definition['version']?>"><input type="hidden" name="request_key" value="<?=playbookEscape($requestKey)?>"><input type="hidden" name="csrf_token" value="<?=playbookEscape($csrf)?>"><button type="submit">Run saved preview</button></form><p class="muted">Retrying this submission returns the same run. Reloading the definition creates a new preview request.</p><?php else:?><p class="muted">Sign in with a named user account to start a preview.</p><?php endif;?></section><?php endif;?>
<section><h2>Case run history</h2><p class="muted"><?=(int)$pagination['total']?> runs, including previews and any executions started through other workflows.</p><div class="scroll"><table><thead><tr><th>Run</th><th>Playbook</th><th>Mode / status</th><th>Analyst</th><th>Started (server time)</th></tr></thead><tbody>
<?php foreach($data['runs'] as $row):?><tr><td><a href="<?=playbookEscape(playbookUrl(['id'=>$id,'run_id'=>$row['id'],'page'=>$pagination['page']]))?>#run">#<?=(int)$row['id']?></a></td><td><?=playbookEscape($row['execution_context']['definition_snapshot']['playbook']['display_name']??$row['display_name'])?><small>version <?=(int)$row['playbook_version']?></small></td><td><?=playbookEscape($row['execution_context']['mode']??'Not recorded')?><small><?=playbookEscape($row['status'])?></small></td><td><?=playbookEscape($row['analyst_name']??'Automation')?></td><td><?=playbookEscape($row['started_at'])?></td></tr><?php endforeach;?>
<?php if(!$data['runs']):?><tr><td colspan="5">No playbook runs for this case yet.</td></tr><?php endif;?></tbody></table></div>
<div class="pager"><span>History page <?=(int)$pagination['page']?> of <?=(int)$pagination['pages']?></span><span><?php if($pagination['page']>1):?><a href="<?=playbookEscape(playbookUrl(['id'=>$id,'page'=>$pagination['page']-1]))?>">Newer</a><?php endif;?> <?php if($pagination['page']<$pagination['pages']):?><a href="<?=playbookEscape(playbookUrl(['id'=>$id,'page'=>$pagination['page']+1]))?>">Older</a><?php endif;?></span></div></section>
<?php endif;?></main></body></html>
