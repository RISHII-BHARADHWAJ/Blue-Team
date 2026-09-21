<?php
/**
 * ThreatPulse SOAR - Playbook Runs API
 * POST /api/v1/playbook_runs.php  - Start a playbook run (Tier 2+)
 *
 * Client may NOT supply: risk_score, priority, severity, incident_number,
 *                        action handlers, class names, arbitrary code.
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/playbooks/PlaybookEngine.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    echo json_encode(['success' => false, 'error' => 'method_not_allowed']);
    exit;
}

// Tier 1 can only do DRY_RUN
$body       = json_decode(file_get_contents('php://input'), true) ?: $_POST;

// Reject server-side fields being injected by client
$serverFields = ['risk_score','priority','severity','incident_number','handler','handler_class','eval','exec'];
foreach ($serverFields as $f) {
    if (isset($body[$f])) {
        http_response_code(422);
        echo json_encode(['success' => false, 'error' => 'tampering_detected', 'message' => "Field '{$f}' may not be supplied by the client."]);
        exit;
    }
}

$incidentId = isset($body['incident_id']) && is_numeric($body['incident_id']) ? (int)$body['incident_id'] : null;
$playbookId = isset($body['playbook_id']) && is_numeric($body['playbook_id']) ? (int)$body['playbook_id'] : null;
$mode       = strtoupper(trim($body['mode'] ?? 'MANUAL'));

if (!$incidentId || !$playbookId) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'missing_fields', 'message' => 'incident_id and playbook_id are required.']);
    exit;
}

// Tier 1 cannot execute live playbooks — forced to DRY_RUN.
// Authorization is derived exclusively from the server-side session via SoarAuth::getContext().
// Client-supplied mode values are accepted only when the caller has 'execute_playbooks' permission.
// 'execute_playbooks' maps to [TIER_2, LEAD, ADMIN] in SoarAuth::hasPermission().
if (!SoarAuth::hasPermission($auth['tier'], 'execute_playbooks')) {
    $mode = 'DRY_RUN';
}

try {
    $engine = new PlaybookEngine($pdo);
    $run    = $engine->startRun($playbookId, $incidentId, $mode, [
        'id'       => $auth['user_id'] ?? 0,
        'username' => $auth['actor'],
        'tier'     => $auth['tier'],  // Server-side resolved; NEVER from client input
    ]);
    echo json_encode(['success' => true, 'action' => 'run_started', 'data' => $run], JSON_UNESCAPED_SLASHES);
} catch (InvalidArgumentException $e) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'not_found', 'message' => $e->getMessage()]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to start playbook run.']);
}
