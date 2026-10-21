<?php
/** Persistent collection health, history and administrator schedule settings. */
declare(strict_types=1);
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/intel/FeedRepository.php';
require_once __DIR__ . '/includes/soar/SoarCsrf.php';
$auth=SoarAuth::getContext($pdo);
if ($auth['auth_method']==='anonymous') { header('Location: login.php'); exit; }
if (!SoarAuth::hasPermission($auth['tier'],'view_alerts')) { http_response_code(403); exit('Not authorized.'); }
header('X-Frame-Options: DENY'); header('X-Content-Type-Options: nosniff'); header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
function feedEscape(mixed $v): string { return htmlspecialchars((string)($v??''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function feedUrl(array $p): string { return 'feeds.php?'.http_build_query($p); }
$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));
$canManage=$auth['auth_method']==='session' && !empty($auth['user_id']) && SoarAuth::hasPermission($auth['tier'],'admin_operations');
$provider=is_string($_GET['provider']??null)?$_GET['provider']:'';
$status=is_string($_GET['status']??null)?$_GET['status']:'';
$page=filter_var($_GET['page']??1,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])?:1;
$repo=new FeedRepository($pdo); $error=null; $sources=[]; $history=null;
try {
    if ($_SERVER['REQUEST_METHOD']==='POST') {
        if (!$canManage) { http_response_code(403); exit('Only named administrators can configure feeds.'); }
        SoarCsrf::enforce($auth);
        $repo->configure(is_string($_POST['provider']??null)?$_POST['provider']:'',$_POST,(int)$auth['user_id']);
        header('Location: feeds.php?saved=1',true,303); exit;
    }
    if ($_SERVER['REQUEST_METHOD']!=='GET') { header('Allow: GET, POST'); http_response_code(405); exit('Method not allowed.'); }
    $sources=$repo->sources(); $history=$repo->history($provider,$status,$page);
} catch (UnexpectedValueException $e) { http_response_code(403); $error=$e->getMessage(); }
catch (InvalidArgumentException $e) { http_response_code(422); $error=$e->getMessage(); }
catch (DomainException $e) { http_response_code(409); $error=$e->getMessage(); }
catch (Throwable $e) { http_response_code(503); $error='Feed history is unavailable. Check database health and apply migration 010.'; }
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Feed health</title><link rel="stylesheet" href="assets/css/workspace.css"></head><body>
<a class="skip" href="#main">Skip to feed health</a><div class="workspace"><aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a>
<nav aria-label="SOC navigation"><a href="soc.php">Overview</a><a href="events.php">Event evidence</a><a href="detections.php">Detections</a><a href="threat-intel.php">Threat intelligence</a><a href="feeds.php" aria-current="page">Feed health</a><a href="incidents.php">Incidents</a><a href="control_plane/index.php">SOAR approvals</a></nav>
<p>External intelligence collection<br>All times are UTC</p></aside><main id="main"><span class="eyebrow">Operations / collection</span><h1>Feed health</h1>
<p>Inspect collection results and refresh schedules. Feed listings are external reputation context, never evidence of attacks against this environment.</p>
<?php if (getenv('FEED_COLLECTION_ENABLED')==='0'): ?><div class="notice">Collection is paused by the deployment setting. The history below reflects earlier runs; schedules will resume when collection is enabled.</div><?php endif; ?>
<?php if ($error): ?><div class="notice error" role="alert"><?= feedEscape($error) ?> <a href="feeds.php">Reload settings</a></div><?php endif; ?>
<?php if (isset($_GET['saved']) && !$error): ?><div class="notice" role="status">Feed settings saved and audited. They apply at the next scheduler check; a running collection may finish.</div><?php endif; ?>
<?php if ($sources): ?><section class="panel"><h2>Collection status</h2><p>Healthy means the last run completed without omissions and is within its expected refresh interval plus a two-minute grace period. It does not certify upstream intelligence accuracy.</p>
<div class="table-wrap"><table><thead><tr><th>Feed</th><th>Health</th><th>Last attempt / complete success</th><th>Next eligible check</th><th>Latest result</th></tr></thead><tbody>
<?php foreach ($sources as $source): ?><tr><td><?= feedEscape(FeedCatalog::FEEDS[$source['provider']]['name']??$source['provider']) ?><br>Every <?= feedEscape($source['refresh_seconds']) ?> seconds</td><td><span class="badge"><?= feedEscape($source['health']) ?></span></td><td><?= feedEscape($source['last_attempt_at']??'Never attempted') ?><br><span class="muted">Complete success: <?= feedEscape($source['last_success_at']??'None recorded') ?></span></td><td><?= feedEscape($source['enabled']?($source['next_due_at']??'Next scheduler check'):'Disabled') ?></td><td><?= feedEscape($source['detail']??'No recorded attempts') ?><br><a href="<?= feedEscape(feedUrl(['provider'=>$source['provider']])) ?>#history">View history</a></td></tr><?php endforeach; ?>
</tbody></table></div></section><?php endif; ?>
<?php if ($history): ?><section class="panel" id="history"><div class="panel-head"><h2>Collection history</h2><span><?= feedEscape($history['total']) ?> recorded attempts</span></div>
<form method="get" class="filters"><div class="field"><label for="provider">Feed</label><select id="provider" name="provider"><option value="">All feeds</option><?php foreach (FeedCatalog::FEEDS as $key=>$feed): ?><option value="<?= feedEscape($key) ?>" <?= $provider===$key?'selected':'' ?>><?= feedEscape($feed['name']) ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="status">Run result</label><select id="status" name="status"><option value="">All results</option><?php foreach (['RUNNING','SUCCESS','PARTIAL','FAILED','INTERRUPTED'] as $value): ?><option <?= $status===$value?'selected':'' ?>><?= feedEscape($value) ?></option><?php endforeach; ?></select></div><button type="submit">Filter history</button></form>
<div class="table-wrap"><table><thead><tr><th>Run / feed</th><th>Started / finished</th><th>Result / HTTP</th><th>Committed indicators</th><th>Collection details</th></tr></thead><tbody>
<?php foreach ($history['rows'] as $run): ?><tr><td>#<?= feedEscape($run['id']) ?> · <?= feedEscape($run['provider']) ?><br><?= feedEscape($run['trigger_kind']) ?> · config revision <?= feedEscape($run['config_revision']) ?></td><td><?= feedEscape($run['started_at']) ?><br><?= feedEscape($run['finished_at']??'Unfinished') ?><br><?= $run['elapsed_ms']!==null?feedEscape($run['elapsed_ms']).' ms':'' ?></td><td><span class="badge"><?= feedEscape($run['status']) ?></span><br>HTTP <?= feedEscape($run['http_status']??'Not received') ?></td><td><?= feedEscape($run['processed_count']) ?> processed<br><?= feedEscape($run['inserted_count']) ?> new / <?= feedEscape($run['existing_count']) ?> existing</td><td><?= feedEscape($run['detail']) ?><br><?= feedEscape($run['bytes_received']) ?> bytes · <?= feedEscape($run['invalid_count']) ?> invalid · <?= feedEscape($run['duplicate_count']) ?> duplicate rows<?php if ($run['truncated']): ?><br><strong>IMPORT CAP REACHED — incomplete inventory refresh</strong><?php endif; ?><details><summary>Collection endpoint</summary><code><?= feedEscape($run['source_url']) ?></code></details></td></tr><?php endforeach; ?>
<?php if (!$history['rows']): ?><tr><td colspan="5" class="empty">No recorded attempts for this filter. Existing imported indicators do not imply a recorded successful collection. History begins after migration 010.</td></tr><?php endif; ?>
</tbody></table></div><div class="pages">Page <?= feedEscape($history['page']) ?> of <?= feedEscape($history['pages']) ?><div>
<?php if ($history['page']>1): ?><a href="<?= feedEscape(feedUrl(['provider'=>$provider,'status'=>$status,'page'=>$history['page']-1])) ?>">Previous</a><?php endif; ?>
<?php if ($history['page']<$history['pages']): ?><a href="<?= feedEscape(feedUrl(['provider'=>$provider,'status'=>$status,'page'=>$history['page']+1])) ?>">Next</a><?php endif; ?></div></div></section><?php endif; ?>
<?php if ($sources): ?><section class="panel"><h2>Refresh settings</h2><p>Schedules are checked every minute. Manual CLI runs bypass the interval but honor disabled feeds. Changes are limited to administrators and do not start a network request from this page.</p>
<?php foreach ($sources as $source): if (!isset(FeedCatalog::FEEDS[$source['provider']])) continue; ?><article><h3><?= feedEscape(FeedCatalog::FEEDS[$source['provider']]['name']) ?></h3><p>Revision <?= feedEscape($source['revision']) ?> · updated <?= feedEscape($source['updated_at']) ?> by <?= feedEscape($source['updated_by']) ?></p>
<?php if ($canManage): ?><form method="post" class="filters"><input type="hidden" name="csrf_token" value="<?= feedEscape($_SESSION['csrf_token']) ?>"><input type="hidden" name="provider" value="<?= feedEscape($source['provider']) ?>"><input type="hidden" name="revision" value="<?= feedEscape($source['revision']) ?>">
<div class="field"><label for="enabled-<?= feedEscape($source['provider']) ?>">Status</label><select name="enabled" id="enabled-<?= feedEscape($source['provider']) ?>"><option value="1" <?= $source['enabled']?'selected':'' ?>>Enabled</option><option value="0" <?= !$source['enabled']?'selected':'' ?>>Disabled</option></select></div>
<div class="field"><label for="interval-<?= feedEscape($source['provider']) ?>">Refresh interval (seconds)</label><input name="refresh_seconds" id="interval-<?= feedEscape($source['provider']) ?>" type="number" min="60" max="86400" required value="<?= feedEscape($source['refresh_seconds']) ?>"></div><button type="submit">Save feed settings</button></form><?php else: ?><p>Schedule management requires an administrator account.</p><?php endif; ?></article><?php endforeach; ?></section><?php endif; ?>
<div class="notice">Imports are capped at 300 Feodo or 2,000 plaintext indicators per run. Removed upstream entries are not deleted locally. ThreatFox is not collected by these scripts; its on-demand enrichment integration is separate.</div>
</main></div></body></html>
