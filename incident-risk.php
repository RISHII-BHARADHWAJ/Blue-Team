<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/SoarAuth.php';
require_once __DIR__ . '/includes/soar/Risk/RiskScoringEngine.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
require_once __DIR__ . '/includes/security.php';
header('Cache-Control: no-store'); header('X-Frame-Options: DENY');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { header('Allow: GET'); http_response_code(405); exit; }
$id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
$page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;
$selectedId = isset($_GET['assessment_id']) ? filter_var($_GET['assessment_id'], FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) : null;
$error = null; $data = null;
try {
    if (!$id || $selectedId === false) { http_response_code(400); $error='Select a valid incident and assessment.'; }
    else $data = (new RiskScoringEngine($pdo))->workspace($id, $page, $selectedId);
} catch (InvalidArgumentException $e) { http_response_code(404); $error=$e->getMessage(); }
catch (Throwable $e) { error_log('Risk workspace failed: '.$e->getMessage()); http_response_code(500); $error='Risk history is unavailable. Check database health and required migrations.'; }
$canRecalculate = SoarAuth::hasPermission($auth['tier'], 'create_incidents') && ($auth['auth_method'] !== 'session' || !empty($auth['user_id']));
$csrf = $canRecalculate ? generateCSRFToken() : '';
function riskEscape(mixed $v): string { return htmlspecialchars((string)($v ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
$labels = ['alert_severity'=>'Severity classification', 'alert_volume'=>'Attached alert count', 'attack_chain'=>'Category pattern', 'ioc_reputation'=>'Indicator reputation', 'ioc_confidence'=>'Indicator confidence', 'ti_agreement'=>'Provider agreement', 'incident_category'=>'Incident category', 'network_context'=>'Reported network context', 'attack_recency'=>'Alert recency', 'asset_criticality'=>'Asset criticality'];
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Incident risk · ThreatPulse</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#091321;color:#e4edf7;font:15px/1.6 system-ui,sans-serif}main{max-width:1160px;margin:auto;padding:28px 22px 60px}nav,.metrics,.actions{display:flex;gap:22px;flex-wrap:wrap;align-items:center}a{color:#74ded1}h1{font-size:32px;line-height:1.2}h2{font-size:20px}section{background:#111f31;border:1px solid #2b415b;border-radius:12px;margin:22px 0;padding:22px}.muted,small{color:#a9bdd1}.metrics>div{flex:1;min-width:145px;padding:12px 0}.value{font-size:32px;font-weight:700;display:block}.notice{color:#ffcf83}button{background:#72ded0;color:#092129;border:0;border-radius:7px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.6}table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:14px 10px;border-bottom:1px solid #294057}th{color:#adbed3;font-size:13px}td:nth-child(3){min-width:85px}.scroll{overflow:auto}progress{width:90px;height:8px;accent-color:#72ded0;display:block}td small{display:block}td{overflow-wrap:anywhere}.error{color:#ffb09c}#feedback{min-height:28px}tr.selected{background:#193449}.pager{display:flex;justify-content:space-between;gap:18px;padding-top:16px}
</style></head><body><main>
<nav><a href="soc.php">SOC overview</a><a href="incidents.php">Incident queue</a></nav>
<h1>Explain the case priority</h1>
<?php if ($error): ?><section class="error" role="alert"><?= riskEscape($error) ?></section><?php endif; ?>
<?php if ($data): $incident=$data['incident']; $assessment=$data['selected']; $latest=$data['latest']; $pagination=$data['pagination']; ?>
<p><a href="incidents.php?id=<?= (int)$id ?>&amp;kind=<?= $incident['is_simulated']?'simulated':'observed' ?>#details"><?= riskEscape($incident['incident_number']) ?> · <?= riskEscape($incident['title']) ?></a></p>
<?php if ($incident['is_simulated']): ?><p class="notice"><strong>SIMULATED TEST DATA</strong> — this score describes a training case.</p><?php endif; ?>
<p class="muted">A policy score helps order investigation work. It is not a probability of compromise or an instruction to contain a host. Confidence describes the available evidence, not certainty that an attack occurred.</p>
<section><h2>Saved assessment</h2>
<?php if ($assessment): ?>
<div class="metrics"><div><small>Risk score</small><span class="value"><?= (int)$assessment['score'] ?><small> / 100</small></span></div><div><small>Assessed priority</small><span class="value"><?= riskEscape($assessment['priority']) ?></span></div><div><small>Evidence confidence</small><span class="value"><?= riskEscape($assessment['confidence']) ?></span></div><div><small>Case priority now</small><span class="value"><?= riskEscape($incident['priority']) ?></span></div></div>
<p>Assessment #<?= (int)$assessment['id'] ?> · <?= riskEscape($assessment['calculated_at']) ?> UTC · <?= riskEscape($assessment['calculated_by']) ?> · Policy <?= riskEscape($assessment['policy_version']) ?></p>
<?php if ((int)$assessment['id'] !== (int)$latest['id']): ?><p class="notice">Viewing a historical assessment. <a href="incident-risk.php?id=<?= (int)$id ?>">View latest</a></p><?php endif; ?>
<?php if ($assessment['policy_version'] !== RiskPolicy::VERSION): ?><p class="notice">This snapshot uses an earlier policy. Recalculate explicitly to apply <?= riskEscape(RiskPolicy::VERSION) ?>; historical results remain unchanged.</p><?php endif; ?>
<p class="muted">This is a saved snapshot. New alerts, provider results, and elapsed time can change a later calculation. Incident correlation may also change the case priority after this assessment.</p>
<?php else: ?><p><strong>No saved risk assessment.</strong> The case has a severity-based priority; an uncalculated score is not evidence of low risk.</p><?php endif; ?>
<div class="actions"><?php if ($canRecalculate): ?><button id="recalculate" type="button" data-csrf="<?= riskEscape($csrf) ?>" data-incident-id="<?= (int)$id ?>">Recalculate risk and priority</button><?php else: ?><span class="muted">Tier 2 or higher is required to recalculate.</span><?php endif; ?></div>
<p class="muted">Recalculation saves an assessment and updates this case's priority using stored evidence. It does not query providers or start response actions. Missing, failed, or expired intelligence adds no reputation evidence.</p><div id="feedback" role="status" aria-live="polite"></div>
</section>
<?php if ($assessment): ?><section><h2>Where the points came from</h2><p class="muted">Factor contributions are added, then capped at 100. Priority thresholds: P1 ≥ 90, P2 ≥ 75, P3 ≥ 50, P4 &lt; 50.</p><div class="scroll"><table><thead><tr><th>Factor</th><th>Recorded basis</th><th>Points</th><th>Explanation</th></tr></thead><tbody>
<?php foreach ($assessment['factor_breakdown'] as $factor): ?><tr><td><?= riskEscape($labels[$factor['name'] ?? ''] ?? $factor['name'] ?? '') ?></td><td><?= riskEscape($factor['value'] ?? '') ?></td><td>+<?= (int)($factor['contribution'] ?? 0) ?> / <?= (int)($factor['max_possible'] ?? 0) ?><progress value="<?= (int)($factor['contribution'] ?? 0) ?>" max="<?= max(1,(int)($factor['max_possible'] ?? 1)) ?>" aria-label="<?= riskEscape($labels[$factor['name'] ?? ''] ?? 'Factor points') ?>"></progress></td><td><?= riskEscape($factor['reason'] ?? '') ?></td></tr><?php endforeach; ?>
</tbody></table></div><p><a href="incidents.php?id=<?= (int)$id ?>&amp;kind=<?= $incident['is_simulated']?'simulated':'observed' ?>#details">Inspect linked case evidence</a></p></section><?php endif; ?>
<section><h2>Assessment history</h2><p class="muted"><?= (int)$pagination['total'] ?> saved assessments. Select a row to inspect its original factor breakdown.</p><div class="scroll"><table><thead><tr><th>Assessment</th><th>Calculated (UTC)</th><th>Score</th><th>Priority</th><th>Confidence</th><th>Policy / analyst</th></tr></thead><tbody>
<?php foreach ($data['history'] as $row): ?><tr class="<?= $assessment && (int)$assessment['id']===(int)$row['id']?'selected':'' ?>"><td><a href="incident-risk.php?id=<?= (int)$id ?>&amp;assessment_id=<?= (int)$row['id'] ?>&amp;page=<?= (int)$pagination['page'] ?>">#<?= (int)$row['id'] ?></a></td><td><?= riskEscape($row['calculated_at']) ?></td><td><?= (int)$row['score'] ?></td><td><?= riskEscape($row['priority']) ?></td><td><?= riskEscape($row['confidence']) ?></td><td><?= riskEscape($row['policy_version']) ?><small><?= riskEscape($row['calculated_by']) ?></small></td></tr><?php endforeach; ?>
<?php if (!$data['history']): ?><tr><td colspan="6">No assessments yet.</td></tr><?php endif; ?></tbody></table></div>
<div class="pager"><span>Page <?= (int)$pagination['page'] ?> of <?= (int)$pagination['pages'] ?></span><span><?php if ($pagination['page']>1): ?><a href="incident-risk.php?id=<?= (int)$id ?>&amp;page=<?= (int)$pagination['page']-1 ?>">Newer</a><?php endif; ?> <?php if ($pagination['page']<$pagination['pages']): ?><a href="incident-risk.php?id=<?= (int)$id ?>&amp;page=<?= (int)$pagination['page']+1 ?>">Older</a><?php endif; ?></span></div></section>
<?php endif; ?>
<script>
const button=document.getElementById('recalculate');
if(button) button.addEventListener('click',async()=>{
 const feedback=document.getElementById('feedback');button.disabled=true;feedback.textContent='Calculating from stored evidence…';
 try{
  const response=await fetch('api/v1/incidents_risk.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':button.dataset.csrf},body:JSON.stringify({incident_id:Number(button.dataset.incidentId)})});
  const result=await response.json();
  if(!response.ok || !result.success){feedback.textContent=result.message || 'Recalculation failed.';return;}
  window.location.assign('incident-risk.php?id='+encodeURIComponent(button.dataset.incidentId));
 }catch(_){feedback.textContent='Could not confirm the result. Reload this page to check the saved history before retrying.';}
 finally{button.disabled=false;}
});
</script></main></body></html>
