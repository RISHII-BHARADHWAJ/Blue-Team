<?php
/**
 * ThreatPulse SOAR - Playbooks REST API
 * GET  /api/v1/playbooks.php   - List active playbooks (Tier 1+)
 * POST /api/v1/playbooks.php   - Create playbook definition (Admin only)
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/SoarCsrf.php';
require_once __DIR__ . '/../../includes/soar/playbooks/PlaybookRepository.php';
require_once __DIR__ . '/../../includes/soar/playbooks/PlaybookValidator.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized']);
    exit;
}

$repo      = new PlaybookRepository($pdo);
$validator = new PlaybookValidator($pdo);
$method    = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $category = !empty($_GET['category']) ? strtoupper(trim($_GET['category'])) : null;
    $playbooks = $repo->findActivePlaybooks($category ? ['category' => $category] : []);
    echo json_encode(['success' => true, 'count' => count($playbooks), 'data' => $playbooks], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($method === 'POST') {
    SoarCsrf::enforce($auth);
    // Only ADMIN tier may create or modify playbook definitions.
    // 'manage_playbooks' maps to [ADMIN] in SoarAuth::hasPermission().
    if (!SoarAuth::hasPermission($auth['tier'], 'manage_playbooks')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => 'Only Admin users may create playbook definitions.']);
        exit;
    }

    $body  = json_decode(file_get_contents('php://input'), true) ?: $_POST;

    // Reject dangerous fields upfront
    foreach (['handler', 'handler_class', 'exec', 'eval', 'shell'] as $forbidden) {
        if (isset($body[$forbidden])) {
            http_response_code(422);
            echo json_encode(['success' => false, 'error' => 'tampering_detected', 'message' => "Field '{$forbidden}' is not allowed."]);
            exit;
        }
    }

    $steps  = $body['steps'] ?? [];
    $errors = $validator->validate($body, $steps);
    if (!empty($errors)) {
        http_response_code(422);
        echo json_encode(['success' => false, 'error' => 'validation_failed', 'errors' => $errors]);
        exit;
    }

    try {
        $playbookId = $repo->createPlaybook($body, (int)($auth['user_id'] ?? 0));
        foreach ($steps as $step) {
            $repo->createStep($playbookId, $step);
        }
        echo json_encode(['success' => true, 'action' => 'created', 'playbook_id' => $playbookId]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to create playbook.']);
    }
    exit;
}

http_response_code(405);
header('Allow: GET, POST');
echo json_encode(['success' => false, 'error' => 'method_not_allowed']);
