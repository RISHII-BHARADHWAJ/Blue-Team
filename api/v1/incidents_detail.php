<?php
/**
 * ThreatPulse SOAR - Incident Detail & Lifecycle Management Endpoint
 * 
 * Endpoint: /api/v1/incidents_detail.php
 * 
 * Methods Supported:
 * - GET: Retrieve complete incident record with attached SIEM alerts, timeline, and IOCs
 * - POST: State transitions (change_status), analyst assignments (assign), and alert attachments (attach_alert)
 * 
 * Security:
 * - RBAC enforcement (Tier 1 view, Tier 2 assign/progress, Lead close)
 * - State machine validation
 * - CSRF / API Bearer auth
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/SoarCsrf.php';
require_once __DIR__ . '/../../includes/soar/IncidentManager.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized', 'message' => 'Authentication required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$manager = new IncidentManager($pdo);
$method = $_SERVER['REQUEST_METHOD'];

// -----------------------------------------------------------------------------
// GET: Incident Detail
// -----------------------------------------------------------------------------
if ($method === 'GET') {
    $incidentId = isset($_GET['id']) && is_numeric($_GET['id']) ? (int)$_GET['id'] : null;
    $incidentNum = !empty($_GET['number']) ? trim((string)$_GET['number']) : null;

    if (!$incidentId && !$incidentNum) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'missing_identifier', 'message' => 'Provide incident ?id= or ?number='], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $repo = new IncidentRepository($pdo);
    $incident = $incidentId ? $manager->getIncident($incidentId) : null;
    if (!$incident && $incidentNum) {
        $found = $repo->findByNumber($incidentNum);
        if ($found) {
            $incident = $manager->getIncident((int)$found['id']);
        }
    }

    if (!$incident) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'not_found', 'message' => 'Incident not found.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    echo json_encode(['success' => true, 'data' => $incident], JSON_UNESCAPED_SLASHES);
    exit;
}

// -----------------------------------------------------------------------------
// POST: Incident State Mutations (Status Transition, Assignment, Alert Link)
// -----------------------------------------------------------------------------
if ($method === 'POST') {
    SoarCsrf::enforce($auth);
    $rawInput = file_get_contents('php://input');
    $body = json_decode($rawInput, true) ?: $_POST;

    $incidentId = isset($body['id']) && is_numeric($body['id']) ? (int)$body['id'] : null;
    $action = !empty($body['action']) ? trim((string)$body['action']) : '';

    if (!$incidentId) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'missing_incident_id', 'message' => 'Incident id is required.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    try {
        switch ($action) {
            case 'change_status':
                $newStatus = !empty($body['new_status']) ? trim((string)$body['new_status']) : '';
                $reason = !empty($body['reason']) ? trim((string)$body['reason']) : null;

                if (empty($newStatus)) {
                    http_response_code(422);
                    echo json_encode(['success' => false, 'error' => 'missing_status', 'message' => 'new_status parameter is required.'], JSON_UNESCAPED_SLASHES);
                    exit;
                }

                $updated = $manager->changeStatus($incidentId, $newStatus, $auth['actor'], $reason);
                echo json_encode(['success' => true, 'action' => 'status_changed', 'data' => $updated], JSON_UNESCAPED_SLASHES);
                exit;

            case 'assign':
                $analystId = isset($body['analyst_id']) && is_numeric($body['analyst_id']) ? (int)$body['analyst_id'] : null;
                if (!$analystId) {
                    http_response_code(422);
                    echo json_encode(['success' => false, 'error' => 'missing_analyst_id', 'message' => 'analyst_id is required.'], JSON_UNESCAPED_SLASHES);
                    exit;
                }

                $updated = $manager->assignIncident($incidentId, $analystId, $auth['actor']);
                echo json_encode(['success' => true, 'action' => 'assigned', 'data' => $updated], JSON_UNESCAPED_SLASHES);
                exit;

            case 'attach_alert':
                $logId = isset($body['log_id']) && is_numeric($body['log_id']) ? (int)$body['log_id'] : null;
                if (!$logId) {
                    http_response_code(422);
                    echo json_encode(['success' => false, 'error' => 'missing_log_id', 'message' => 'log_id is required.'], JSON_UNESCAPED_SLASHES);
                    exit;
                }

                $updated = $manager->attachAlert($incidentId, $logId, 'MANUAL_ATTACHMENT', $auth['actor']);
                echo json_encode(['success' => true, 'action' => 'alert_attached', 'data' => $updated], JSON_UNESCAPED_SLASHES);
                exit;

            default:
                http_response_code(422);
                echo json_encode(['success' => false, 'error' => 'unknown_action', 'message' => "Supported actions: 'change_status', 'assign', 'attach_alert'."], JSON_UNESCAPED_SLASHES);
                exit;
        }

    } catch (InvalidStateTransitionException $e) {
        http_response_code(422);
        echo json_encode(['success' => false, 'error' => 'invalid_state_transition', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
        exit;
    } catch (DomainException $e) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
        exit;
    } catch (InvalidArgumentException $e) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'not_found', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
        exit;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Action processing failed.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

http_response_code(405);
header('Allow: GET, POST');
echo json_encode(['success' => false, 'error' => 'method_not_allowed'], JSON_UNESCAPED_SLASHES);
exit;
