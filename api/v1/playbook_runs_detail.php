<?php
/**
 * ThreatPulse SOAR - Playbook Run Detail API
 * GET /api/v1/playbook_runs_detail.php?id=123
 *
 * Returns full run status, incident reference, playbook, completed steps,
 * approvals, action results, and timestamps.
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/playbooks/PlaybookRepository.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    echo json_encode(['success' => false, 'error' => 'method_not_allowed']);
    exit;
}

$runId = isset($_GET['id']) && is_numeric($_GET['id']) ? (int)$_GET['id'] : null;
if (!$runId) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'missing_id', 'message' => '?id= parameter is required.']);
    exit;
}

$repo = new PlaybookRepository($pdo);
$run  = $repo->findRun($runId);

if (!$run) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'not_found', 'message' => "Run #{$runId} not found."]);
    exit;
}

// IDOR: verify requesting analyst owns or can view the run
// For now all authenticated analysts may view runs (Tier 1+)
$stepResults = $repo->getStepResults($runId);
$approval    = $repo->findPendingApproval($runId);
$steps       = $repo->getSteps((int)$run['playbook_id']);

echo json_encode([
    'success' => true,
    'data'    => [
        'run'          => $run,
        'steps'        => $steps,
        'step_results' => $stepResults,
        'approval'     => $approval,
    ]
], JSON_UNESCAPED_SLASHES);
