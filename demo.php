<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/DemoService.php';
require_once __DIR__ . '/includes/soar/SoarCsrf.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
require_once __DIR__ . '/includes/security.php';
header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY'); header('Cache-Control: no-store');
$canStart = $auth['auth_method'] === 'session' && !empty($auth['user_id']) && SoarAuth::hasPermission($auth['tier'], 'create_incidents');
$service = new DemoService($pdo); $error = null; $session = null; $incident = null; $run = null; $steps = [];
function demoEscape(mixed $v): string { return htmlspecialchars((string)($v ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!$canStart) { http_response_code(403); exit('A named Tier 2 or higher account is required.'); }
        SoarCsrf::enforce($auth);
        $action = $_POST['action'] ?? '';
        if ($action === 'create' && is_string($_POST['request_key'] ?? null)) {
            $session = $service->create((int)$auth['user_id'], $_POST['request_key']);
        } elseif ($action === 'preview') {
            $id = filter_var($_POST['session_id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
            if (!$id) throw new InvalidArgumentException('A demo session ID is required.');
            $session = $service->preview($id, (int)$auth['user_id']);
        } else throw new InvalidArgumentException('Unknown demo action.');
        header('Location: demo.php?id=' . (int)$session['id'], true, 303); exit;
    }
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') { header('Allow: GET, POST'); http_response_code(405); exit; }
    $id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
    if ($id) {
        $session = $service->find($id);
        if (!$session) { http_response_code(404); $error = 'Demo not found.'; }
        else {
            $incident = (new IncidentManager($pdo))->getIncident((int)$session['incident_id']);
            if ($session['playbook_run_id']) {
                $run = (new PlaybookRepository($pdo))->findRun((int)$session['playbook_run_id']);
                $stmt = $pdo->prepare('SELECT step_order, action_type, status, output, is_dry_run FROM playbook_step_results WHERE playbook_run_id = ? ORDER BY step_order, id');
                $stmt->execute([$session['playbook_run_id']]); $steps = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }
        }
    }
} catch (DomainException $e) { http_response_code(403); $error=$e->getMessage(); }
catch (InvalidArgumentException $e) { http_response_code(422); $error=$e->getMessage(); }
catch (UnexpectedValueException $e) { http_response_code(409); $error=$e->getMessage(); }
catch (Throwable $e) { error_log('Demo failed: ' . $e->getMessage()); http_response_code(500); $error='Could not complete the demo. Retry the same request; completed steps are preserved without duplication.'; }
$csrf = $canStart ? generateCSRFToken() : '';
$requestKey = is_string($_POST['request_key'] ?? null) && preg_match('/^[a-f0-9]{32}$/D', $_POST['request_key']) ? $_POST['request_key'] : bin2hex(random_bytes(16));
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Simulated investigation · ThreatPulse</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0c1321;color:#e2ebf6;font:16px/1.6 system-ui,sans-serif}main{max-width:1000px;margin:auto;padding:28px 22px 60px}nav{display:flex;gap:24px;flex-wrap:wrap}a{color:#71dbd2}h1{font-size:34px;line-height:1.2}h2{font-size:21px}section{background:#141f30;border:1px solid #30435b;border-radius:14px;padding:24px;margin:20px 0}.label{color:#ffd488;font-weight:700;letter-spacing:.06em}small,.muted{color:#a9b8cc}button{background:#72ded0;color:#092129;border:0;border-radius:7px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.6}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}.error{border-color:#efae71}li{margin:10px 0}.step{border-top:1px solid #30435b;padding:16px 0}
</style></head><body><main>
<nav><a href="soc.php">SOC overview</a><a href="incidents.php">Incident queue</a><a href="detections.php">Detections</a></nav>
<p class="label">SIMULATED TEST DATA</p><h1>Walk through an investigation</h1>
<p>Generate labeled authentication failures, inspect the rule that detects them, investigate a training case, and preview a SOAR playbook.</p>
<p class="muted">This creates persistent training records using documentation IP 192.0.2.55. No real login attempt or containment takes place. Playbook actions are previews; live enrichment is disabled.</p>
<?php if ($error): ?><section class="error" role="alert"><?= demoEscape($error) ?></section><?php endif; ?>
<?php if (!$session): ?><section><h2>Start a training case</h2><p>The demo uses your current authentication-failure threshold and severity. It leaves rule settings unchanged. Each start creates a separate case; retrying the same submission returns that case.</p>
<?php if ($canStart): ?><form method="post"><input type="hidden" name="csrf_token" value="<?= demoEscape($csrf) ?>"><input type="hidden" name="request_key" value="<?= demoEscape($requestKey) ?>"><input type="hidden" name="action" value="create"><button type="submit">Create simulated incident</button></form>
<?php else: ?><p>Sign in as a Tier 2 analyst or higher to create a training case.</p><?php endif; ?>
<p><a href="incidents.php?kind=simulated">Browse existing simulated cases</a></p></section>
<?php elseif ($incident): ?>
<section><h2>1. Ingestion and detection</h2><p><?= count($incident['alerts']) ?> simulated events were accepted through the ingestion pipeline. The authentication-failure rule produced a finding with its settings and supporting evidence preserved.</p><p><a href="detections.php?kind=simulated&amp;id=<?= (int)$session['finding_id'] ?>">Inspect the detection and its evidence</a></p><small>Created by <?= demoEscape($session['creator']) ?> · <?= demoEscape($session['created_at']) ?> UTC</small></section>
<section><h2>2. Investigate the case</h2><p><strong><?= demoEscape($incident['incident_number']) ?></strong> · <?= demoEscape($incident['severity']) ?> · <?= demoEscape($incident['status']) ?></p><p>Open the case to inspect source evidence, add a case note, assign an analyst, and progress its status through the normal permission checks.</p><p><a href="incidents.php?kind=simulated&amp;id=<?= (int)$incident['id'] ?>#details">Open simulated incident</a></p></section>
<section><h2>3. Preview the SOAR workflow</h2><p>Preview context collection, an approval gate, and an analyst notification. The run and step results are saved; no approval request or notification is sent.</p>
<?php if ($run): ?><p><strong>Run #<?= (int)$run['id'] ?> · <?= demoEscape($run['status']) ?> · DRY_RUN</strong></p>
<?php foreach ($steps as $step): ?><div class="step"><strong><?= (int)$step['step_order'] ?>. <?= demoEscape($step['action_type']) ?></strong><p><?= demoEscape($step['status']) ?> · <?= $step['is_dry_run'] ? 'Preview only' : 'Unexpected non-preview result' ?></p><pre><?= demoEscape((json_decode($step['output'] ?? '{}', true) ?? [])['message'] ?? '') ?></pre></div><?php endforeach; ?>
<?php elseif ($canStart && (int)$session['created_by'] === (int)$auth['user_id']): ?><form method="post"><input type="hidden" name="csrf_token" value="<?= demoEscape($csrf) ?>"><input type="hidden" name="action" value="preview"><input type="hidden" name="session_id" value="<?= (int)$session['id'] ?>"><button type="submit">Run safe playbook preview</button></form>
<?php else: ?><p>The demo creator can start the preview.</p><?php endif; ?>
</section><p><a href="demo.php">Start another training case</a></p>
<?php endif; ?>
</main></body></html>
