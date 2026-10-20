<?php
/**
 * ThreatPulse SOAR - Incidents REST API Endpoint
 * 
 * Endpoint: /api/v1/incidents.php
 * 
 * Methods Supported:
 * - GET: List incidents with filtering (status, severity, priority, assigned_to, date range)
 * - POST: Manually escalate a SIEM alert or create an incident
 * 
 * Security:
 * - Authentication: Active session or Authorization: Bearer <API_KEY>
 * - Authorization: Tier 1+ for GET, Tier 2+ for POST
 * - Strict input validation & parameterized queries
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/SoarCsrf.php';
require_once __DIR__ . '/../../includes/soar/IncidentManager.php';

// 1. Authenticate Request
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error'   => 'unauthorized',
        'message' => 'Authentication required to access incident management.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$manager = new IncidentManager($pdo);
$method = $_SERVER['REQUEST_METHOD'];

// -----------------------------------------------------------------------------
// GET: List Incidents with Filtering & Pagination
// -----------------------------------------------------------------------------
if ($method === 'GET') {
    if (!SoarAuth::hasPermission($auth['tier'], 'view_incidents')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => 'Insufficient permissions to view incidents.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $filters = [
        'status'         => !empty($_GET['status']) ? strtoupper(trim($_GET['status'])) : null,
        'severity'       => !empty($_GET['severity']) ? strtoupper(trim($_GET['severity'])) : null,
        'priority'       => !empty($_GET['priority']) ? strtoupper(trim($_GET['priority'])) : null,
        'assigned_to'    => isset($_GET['assigned_to']) && is_numeric($_GET['assigned_to']) ? (int)$_GET['assigned_to'] : null,
        'category'       => !empty($_GET['category']) ? trim($_GET['category']) : null,
        'created_after'  => !empty($_GET['created_after']) ? trim($_GET['created_after']) : null,
        'created_before' => !empty($_GET['created_before']) ? trim($_GET['created_before']) : null,
    ];

    $limit = isset($_GET['limit']) && is_numeric($_GET['limit']) ? (int)$_GET['limit'] : 50;
    $offset = isset($_GET['offset']) && is_numeric($_GET['offset']) ? (int)$_GET['offset'] : 0;

    try {
        $incidents = $manager->listIncidents($filters, $limit, $offset);
        
        echo json_encode([
            'success' => true,
            'count'   => count($incidents),
            'limit'   => $limit,
            'offset'  => $offset,
            'data'    => $incidents
        ], JSON_UNESCAPED_SLASHES);
        exit;

    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to retrieve incidents.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

// -----------------------------------------------------------------------------
// POST: Manually Escalate Alert or Create Incident
// -----------------------------------------------------------------------------
if ($method === 'POST') {
    SoarCsrf::enforce($auth);
    if (!SoarAuth::hasPermission($auth['tier'], 'create_incidents')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => 'Tier 1 analysts cannot create incidents. Requires Tier 2 or higher.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $rawInput = file_get_contents('php://input');
    $body = json_decode($rawInput, true) ?: $_POST;

    // Route A: Manual Escalation from existing SIEM log_id
    if (!empty($body['log_id'])) {
        $logId = (int)$body['log_id'];
        $title = !empty($body['title']) ? trim((string)$body['title']) : null;
        $desc = !empty($body['description']) ? trim((string)$body['description']) : null;

        try {
            $result = $manager->escalateAlertToIncident($logId, $auth['actor'], $title, $desc);
            http_response_code(201);
            echo json_encode($result, JSON_UNESCAPED_SLASHES);
            exit;
        } catch (InvalidArgumentException $e) {
            http_response_code(422);
            echo json_encode(['success' => false, 'error' => 'invalid_input', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
            exit;
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Escalation failed.'], JSON_UNESCAPED_SLASHES);
            exit;
        }
    }

    // Route B: Manual Incident Creation
    if (!empty($body['title'])) {
        try {
            $incident = $manager->createIncident([
                'title'           => trim((string)$body['title']),
                'description'     => !empty($body['description']) ? trim((string)$body['description']) : '',
                'severity'        => !empty($body['severity']) ? strtoupper(trim((string)$body['severity'])) : 'MEDIUM',
                'attack_category' => !empty($body['attack_category']) ? trim((string)$body['attack_category']) : 'Other',
                'assigned_to'     => !empty($body['assigned_to']) ? (int)$body['assigned_to'] : null,
            ], null, null, $auth['actor'], 'MANUAL_CREATION');

            http_response_code(201);
            echo json_encode([
                'success'  => true,
                'action'   => 'incident_created',
                'incident' => $incident
            ], JSON_UNESCAPED_SLASHES);
            exit;

        } catch (Exception $e) {
            http_response_code(422);
            echo json_encode(['success' => false, 'error' => 'creation_failed', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
            exit;
        }
    }

    http_response_code(422);
    echo json_encode(['success' => false, 'error' => 'missing_parameters', 'message' => 'Either log_id (for escalation) or title (for manual creation) is required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

http_response_code(405);
header('Allow: GET, POST');
echo json_encode(['success' => false, 'error' => 'method_not_allowed'], JSON_UNESCAPED_SLASHES);
exit;
