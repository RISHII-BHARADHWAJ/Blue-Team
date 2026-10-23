<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/SoarCsrf.php';
require_once __DIR__.'/includes/soar/IncidentIocWorkspace.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
require_once __DIR__.'/includes/security.php';
header('Cache-Control: no-store'); header('X-Frame-Options: DENY');
function iocEscape(mixed $value): string { return htmlspecialchars((string)($value ?? ''), ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
function iocUrl(array $params): string { return 'incident-iocs.php?'.http_build_query(array_filter($params,fn($v)=>$v!==null&&$v!=='')); }
function iocId(mixed $value): int|false { return filter_var($value,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]); }
$canDiscover = $auth['auth_method'] === 'session' && !empty($auth['user_id']) && SoarAuth::hasPermission($auth['tier'],'create_incidents');
$id = iocId($_POST['id'] ?? $_GET['id'] ?? null);
$selectedId = isset($_GET['ioc_id']) ? iocId($_GET['ioc_id']) : null;
$page = iocId($_GET['page'] ?? 1); $historyPage = iocId($_GET['history_page'] ?? 1);
$type = is_string($_GET['type'] ?? '') ? ($_GET['type'] ?? '') : '!invalid';
$data = null; $error = null; $notice = null; $service = new IncidentIocWorkspace($pdo);
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!$canDiscover) throw new DomainException('A named Tier 2 or higher analyst is required.');
        SoarCsrf::enforce($auth);
        foreach (array_keys($_POST) as $field) if (!in_array($field,['id','csrf_token'],true)) throw new InvalidArgumentException('Only the case ID may be submitted for local discovery.');
        if (!$id) throw new InvalidArgumentException('Select a valid case.');
        $result = $service->discover($id,(int)$auth['user_id']);
        $_SESSION['ioc_discovery_notice'][$id] = "Discovered {$result['candidate_count']} candidate indicators across {$result['alert_count']} saved alerts; added {$result['new_links']} new case links.";
        header('Location: '.iocUrl(['id'=>$id]),true,303); exit;
    }
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') { header('Allow: GET, POST'); http_response_code(405); exit; }
    if (!$id || $selectedId === false || !$page || !$historyPage) throw new InvalidArgumentException('Select valid case, indicator and page numbers.');
    $data = $service->read($id,$page,$selectedId,$historyPage,$type);
    $notice = $_SESSION['ioc_discovery_notice'][$id] ?? null;
    unset($_SESSION['ioc_discovery_notice'][$id]);
} catch (DomainException $e) { http_response_code(403); $error=$e->getMessage(); }
catch (OutOfBoundsException $e) { http_response_code(404); $error=$e->getMessage(); }
catch (UnexpectedValueException $e) { http_response_code(409); $error=$e->getMessage(); }
catch (InvalidArgumentException $e) { http_response_code(422); $error=$e->getMessage(); }
catch (Throwable $e) { error_log('IOC workspace failed: '.$e->getMessage()); http_response_code(500); $error='Could not load or update case indicators. Check database health and required migrations.'; }
$csrf = $canDiscover ? generateCSRFToken() : '';
$assessmentLabels = ['UNKNOWN'=>'Unknown', 'MALICIOUS'=>'Malicious report', 'SUSPICIOUS'=>'Suspicious report', 'CONFLICTING'=>'Conflicting reports', 'LOW_REPUTATION'=>'Low reputation reported'];
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Incident indicators · ThreatPulse</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0a1422;color:#e4edf7;font:15px/1.6 system-ui,sans-serif}main{max-width:1160px;margin:auto;padding:28px 22px 60px}nav,.pager,.actions{display:flex;gap:20px;flex-wrap:wrap;align-items:center}nav{margin-bottom:24px}a{color:#76dfd2}h1{font-size:32px;line-height:1.2}h2{font-size:21px}section{background:#122033;border:1px solid #2a425e;border-radius:12px;margin:22px 0;padding:22px}.muted,small{color:#a9bed3}.notice{color:#ffd083}.error{color:#ffb19c}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:18px}.metrics strong{font-size:22px;display:block}.metrics small{display:block}button{background:#73dfd0;color:#092129;border:0;border-radius:7px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer}select{font:inherit;padding:9px;border:1px solid #42617d;border-radius:6px;background:#0a1422;color:#e4edf7}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:12px 10px;border-bottom:1px solid #2a425e;vertical-align:top}th{color:#a9bed3}td small{display:block}.scroll{overflow:auto}.pill{border:1px solid #42617d;padding:3px 8px;border-radius:5px;display:inline-block}.indicator{overflow-wrap:anywhere;font-family:ui-monospace,monospace}.pager{justify-content:space-between;padding-top:16px}.selected{background:#1a3043}:focus-visible{outline:3px solid #ffd083;outline-offset:3px}
</style></head><body><main>
<nav><a href="soc.php">SOC overview</a><a href="incidents.php">Incident queue</a><a href="threat-intel.php">Feed inventory</a></nav>
<?php if ($error): ?><h1>Case indicators unavailable</h1><p class="error" role="alert"><?= iocEscape($error) ?></p><?php if ($id): ?><a href="<?= iocEscape(iocUrl(['id'=>$id])) ?>">Reload case indicators</a><?php endif; ?>
<?php else: $incident=$data['incident']; $pagination=$data['pagination']; $selected=$data['selected']; ?>
<p class="muted"><?= iocEscape($incident['incident_number']) ?> / Investigation</p><h1>Indicators &amp; intelligence</h1><p><?= iocEscape($incident['title']) ?></p>
<nav><a href="incidents.php?id=<?= (int)$id ?>&amp;kind=<?= $incident['is_simulated']?'simulated':'observed' ?>#details">Back to case evidence</a><a href="incident-risk.php?id=<?= (int)$id ?>">Risk explanation</a><a href="incident-playbooks.php?id=<?= (int)$id ?>">Playbook previews</a></nav>
<?php if ($incident['is_simulated']): ?><p class="notice">SIMULATED TEST DATA — discovery into the shared inventory is disabled. Use a dry-run playbook to inspect the training case.</p><?php endif; ?>
<?php if ($notice): ?><p role="status" class="notice"><?= iocEscape($notice) ?></p><?php endif; ?>
<section><h2>Discover from case evidence</h2><p>Extract candidate IPs, domains, URLs, hashes and email addresses from saved alerts and preserved metadata. Candidate roles are inferred from telemetry and are not confirmed attacker identities.</p>
<?php if ($canDiscover && !$incident['is_simulated']): ?><form method="post"><input type="hidden" name="id" value="<?= (int)$id ?>"><input type="hidden" name="csrf_token" value="<?= iocEscape($csrf) ?>"><button type="submit">Discover saved indicators</button></form><?php elseif (!$incident['is_simulated']): ?><p class="muted">A named Tier 2 or higher analyst can discover indicators.</p><?php endif; ?>
<p class="muted">Local discovery adds missing links and preserves existing classifications. It makes no provider requests and leaves the case's risk score unchanged. Limits: 1,000 alerts and 2,000 distinct candidates per discovery. The extractor applies its configured private/test-address exclusions; it is not a complete parser for every indicator format.</p></section>
<section><h2>Case indicators</h2><form method="get" class="actions"><input type="hidden" name="id" value="<?= (int)$id ?>"><label for="type">Indicator type</label><select id="type" name="type"><option value="">All types</option><?php foreach (IocNormalizer::SUPPORTED_TYPES as $option): ?><option value="<?= iocEscape($option) ?>" <?= $type===$option?'selected':'' ?>><?= iocEscape($option) ?></option><?php endforeach; ?></select><button type="submit">Filter</button></form>
<p class="muted"><?= (int)$pagination['total'] ?> matching indicators. Intelligence reflects the latest saved result per provider across all cases sharing this indicator. Unknown, expired or failed lookups are not evidence that an indicator is safe.</p>
<div class="scroll"><table><thead><tr><th>Indicator</th><th>Case role</th><th>Saved intelligence</th><th>Linked (server time)</th></tr></thead><tbody>
<?php foreach ($data['iocs'] as $ioc): ?><tr class="<?= $selected && $ioc['id']===$selected['id']?'selected':'' ?>"><td><a href="<?= iocEscape(iocUrl(['id'=>$id,'ioc_id'=>$ioc['id'],'page'=>$pagination['page'],'type'=>$type]).'#indicator') ?>">Inspect #<?= (int)$ioc['id'] ?></a><small><?= iocEscape($ioc['ioc_type']) ?></small><div class="indicator"><?= iocEscape($ioc['ioc_value']) ?></div></td><td><?= iocEscape($ioc['role']) ?></td><td><?= iocEscape($assessmentLabels[$ioc['intelligence']['assessment']]) ?><small><?= (int)$ioc['intelligence']['current_count'] ?> usable current result(s)</small></td><td><?= iocEscape($ioc['discovered_at']) ?></td></tr><?php endforeach; ?>
<?php if (!$data['iocs']): ?><tr><td colspan="4">No indicators match this view. Discover from saved alerts or choose another type.</td></tr><?php endif; ?></tbody></table></div>
<div class="pager"><span>Page <?= (int)$pagination['page'] ?> of <?= (int)$pagination['pages'] ?></span><span><?php if ($pagination['page']>1): ?><a href="<?= iocEscape(iocUrl(['id'=>$id,'page'=>$pagination['page']-1,'type'=>$type])) ?>">Previous</a><?php endif; ?> <?php if ($pagination['page']<$pagination['pages']): ?><a href="<?= iocEscape(iocUrl(['id'=>$id,'page'=>$pagination['page']+1,'type'=>$type])) ?>">Next</a><?php endif; ?></span></div></section>
<?php if ($selected): $intel=$selected['intelligence']; ?>
<section id="indicator"><h2>Indicator #<?= (int)$selected['id'] ?></h2><p class="indicator"><?= iocEscape($selected['ioc_value']) ?></p><div class="metrics"><div><small>Type / case role</small><strong><?= iocEscape($selected['ioc_type']) ?></strong><?= iocEscape($selected['role']) ?></div><div><small>Saved provider assessment</small><strong><?= iocEscape($assessmentLabels[$intel['assessment']]) ?></strong></div><div><small>Registry source</small><?= iocEscape($selected['source_feed']) ?><small>Registry last seen (server time)</small><?= iocEscape($selected['last_seen']) ?></div></div>
<p class="muted">Provider reputation is a signal for investigation, not proof of activity. Scores ≥75 indicate malicious reports; 25–74 indicate suspicious reports. A high-confidence zero score conflicting with a malicious report is shown as conflicting. Low reputation does not establish safety. Registry timestamps can be updated by other workflows and are not provider freshness.</p>
<h2>Latest saved result by provider</h2><?php if ($intel['limited']): ?><p class="notice">Only the first 100 providers are shown; the combined assessment is unknown because this view is incomplete.</p><?php endif; ?>
<div class="scroll"><table><thead><tr><th>Provider</th><th>Result / freshness</th><th>Reputation / confidence</th><th>Retrieved / expires (server time)</th></tr></thead><tbody>
<?php foreach ($intel['providers'] as $row): ?><tr><td><?= iocEscape($row['provider']) ?></td><td><span class="pill"><?= iocEscape($row['state']) ?></span><small><?= iocEscape($row['status']) ?></small></td><td><?= iocEscape($row['reputation'] ?? 'Unavailable') ?> / <?= iocEscape($row['confidence'] ?? 'Unavailable') ?></td><td><?= iocEscape($row['created_at']) ?><small><?= iocEscape($row['cached_until']) ?></small></td></tr><?php endforeach; ?>
<?php if (!$intel['providers']): ?><tr><td colspan="4">No saved provider results. This indicator remains unknown.</td></tr><?php endif; ?></tbody></table></div><p class="muted">CURRENT means a successful, unexpired result with valid scores. INVALID means the saved scores cannot be used. Failed and expired results supersede earlier successes. Raw provider payloads and arbitrary summary fields are not displayed.</p></section>
<section><h2>Saved lookup history</h2><p class="muted">History includes superseded results and does not determine the current assessment. All timestamps use server time.</p><div class="scroll"><table><thead><tr><th>Lookup / provider</th><th>Stored status</th><th>Reputation / confidence</th><th>Retrieved / expires</th></tr></thead><tbody>
<?php foreach ($data['history'] as $row): ?><tr><td>#<?= (int)$row['id'] ?> · <?= iocEscape($row['provider']) ?></td><td><?= iocEscape($row['status']) ?></td><td><?= iocEscape($row['reputation'] ?? 'Unavailable') ?> / <?= iocEscape($row['confidence'] ?? 'Unavailable') ?></td><td><?= iocEscape($row['created_at']) ?><small><?= iocEscape($row['cached_until']) ?></small></td></tr><?php endforeach; ?>
<?php if (!$data['history']): ?><tr><td colspan="4">No stored lookups.</td></tr><?php endif; ?></tbody></table></div>
<?php $hp=$data['historyPagination']; ?><div class="pager"><span><?= (int)$hp['total'] ?> lookups · Page <?= (int)$hp['page'] ?> of <?= (int)$hp['pages'] ?></span><span><?php if ($hp['page']>1): ?><a href="<?= iocEscape(iocUrl(['id'=>$id,'ioc_id'=>$selectedId,'page'=>$page,'type'=>$type,'history_page'=>$hp['page']-1])) ?>">Newer</a><?php endif; ?> <?php if ($hp['page']<$hp['pages']): ?><a href="<?= iocEscape(iocUrl(['id'=>$id,'ioc_id'=>$selectedId,'page'=>$page,'type'=>$type,'history_page'=>$hp['page']+1])) ?>">Older</a><?php endif; ?></span></div></section>
<?php endif; endif; ?>
</main></body></html>
