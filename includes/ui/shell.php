<?php
/** Shared presentation only. Page/API authorization remains authoritative. */
require_once __DIR__.'/../soar/SoarAuth.php';
function tpEscape(mixed $v): string {return htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function tpHead(string $prefix=''): void {echo '<script src="'.$prefix.'assets/js/theme.js"></script><link rel="stylesheet" href="'.$prefix.'assets/css/themes.css"><link rel="stylesheet" href="'.$prefix.'assets/css/design-system.css"><script src="'.$prefix.'assets/js/workspace-shell.js" defer></script>';}
function tpShell(string $page,string $prefix=''): void {
    $tier=SoarAuth::resolveTier($_SESSION['role']??null);
    $actor=$_SESSION['analyst']??$_SESSION['username']??'Analyst';
    $groups=[
        'Observe'=>[['soc.php','Overview','overview'],['events.php','Event evidence','events'],['sources.php','Source activity','sources'],['dashboard.php','Telemetry atlas','atlas']],
        'Investigate'=>[['incidents.php','Cases','cases'],['detections.php','Detections','detections'],['threat-intel.php','Intelligence','intelligence']],
        'Operate'=>[['control_plane/index.php','Approvals','approvals'],['notifications.php','My inbox','inbox'],['feeds.php','Feed health','feeds'],['demo.php','Training lab','training'],['terminal.php','Investigation terminal','terminal']],
    ];
    if(!empty($_SESSION['user_id'])&&SoarAuth::hasPermission($tier,'view_audit'))$groups['Operate'][]=['audit.php','Audit history','audit'];
    $titles=['overview'=>'Operations overview','events'=>'Event evidence','sources'=>'Source activity','atlas'=>'Telemetry atlas','cases'=>'Case workspace','detections'=>'Detection findings','intelligence'=>'Threat intelligence','approvals'=>'Approval control plane','inbox'=>'Personal inbox','feeds'=>'Feed operations','training'=>'Training lab','terminal'=>'Investigation terminal','audit'=>'Audit history'];
?>
<a href="#tp-content" class="tp-skip">Skip to workspace</a>
<aside class="tp-rail" id="tp-navigation" aria-label="Workspace navigation">
<a class="tp-brand" href="<?= $prefix ?>soc.php"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M3 17h7l4-10 6 19 4-9h5"/></svg><span>ThreatPulse<span class="tp-brand-sub">SECURITY OPERATIONS</span></span></a>
<div class="tp-workspace-name"><span class="tp-workspace-mark">TP</span><div>Analyst workspace<small>SIEM + SOAR / Lab edition</small></div></div>
<?php foreach($groups as $label=>$links): ?><div class="tp-nav-group"><span class="tp-nav-label"><?= $label ?></span><nav aria-label="<?= $label ?>"><?php foreach($links as [$url,$text,$key]): ?><a href="<?= $prefix.$url ?>" <?= $page===$key?'aria-current="page"':'' ?>><span class="tp-nav-icon" aria-hidden="true"><?php if($key==='overview'): ?>◫<?php elseif($key==='cases'): ?>▱<?php elseif($key==='events'): ?>≋<?php elseif($key==='approvals'): ?>◇<?php else: ?>·<?php endif; ?></span><?= $text ?><?php if($page===$key): ?><span class="tp-nav-active" aria-hidden="true"></span><?php endif; ?></a><?php endforeach; ?></nav></div><?php endforeach; ?>
<div class="tp-rail-foot"><span class="tp-lab-marker"></span> <?= getenv('APP_ENV') === 'public-demo' ? 'Temporary public demo<small>Saved data resets on restart.</small>' : 'Controlled lab environment<small>Evidence first. Human decisions.</small>' ?></div>
</aside>
<div class="tp-topbar"><button type="button" class="tp-menu" aria-controls="tp-navigation" aria-expanded="false" aria-label="Toggle navigation">☰</button><div class="tp-breadcrumb">Workspace <span>/</span> <strong><?= tpEscape($titles[$page]??'Investigation') ?></strong></div><div class="tp-account"><button type="button" class="tp-theme-toggle" data-theme-toggle aria-label="Switch to dark mode">☾ Dark</button><span class="tp-avatar"><?= tpEscape(strtoupper(substr($actor,0,1))) ?></span><span><?= tpEscape($actor) ?><small><?= tpEscape($tier) ?></small></span><a href="<?= $prefix ?>logout.php" aria-label="Sign out">↗</a></div></div>
<div id="tp-content" tabindex="-1" class="tp-content-anchor"></div>
<?php }
