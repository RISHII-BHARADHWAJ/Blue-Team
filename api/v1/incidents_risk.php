<?php
/**
 * ThreatPulse SOAR - Incident Risk Scoring REST API Endpoint
 * 
 * Endpoint: /api/v1/incidents_risk.php
 * 
 * Methods Supported:
 * - GET: Retrieve current risk assessment, factor breakdown, and full risk history
 * - POST: Trigger deterministic risk recalculation for an incident
 * 
 * Security:
 * - Session or Bearer authentication
 * - Tier 1+ read, Tier 2+ recalculation
 * - Tamper prevention: direct submission of risk_score or priority is strictly rejected
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/Risk/RiskScoringEngine.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized', 'message' => 'Authentication required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$engine = new RiskScoringEngine($pdo);
$method = $_SERVER['REQUEST_METHOD'];

// -----------------------------------------------------------------------------
// GET: Retrieve Current Risk Assessment & History
// -----------------------------------------------------------------------------
if ($method === 'GET') {
    $incidentId = isset($_GET['id']) && is_numeric($_GET['id']) 
        ? (int)$_GET['id'] 
        : (isset($_GET['incident_id']) && is_numeric($_GET['incident_id']) ? (int)$_GET['incident_id'] : null);

    if (!$incidentId) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'missing_incident_id', 'message' => 'Query parameter ?id= is required.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    try {
        $latest = $engine->getLatestAssessment($incidentId);
        $history = $engine->getRiskHistory($incidentId);

        if (!$latest && empty($history)) {
            // Compute on-demand baseline if no assessment has been saved yet
            $assessment = $engine->recalculateIncident($incidentId, $auth['actor']);
            $latest = $engine->getLatestAssessment($incidentId);
            $history = $engine->getRiskHistory($incidentId);
        }

        echo json_encode([
            'success' => true,
            'data'    => [
                'incident_id' => $incidentId,
                'latest'      => $latest,
                'history'     => $history,
            ]
        ], JSON_UNESCAPED_SLASHES);
        exit;

    } catch (InvalidArgumentException $e) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'not_found', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
        exit;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to retrieve risk assessment.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

// -----------------------------------------------------------------------------
// POST: Trigger Deterministic Recalculation
// -----------------------------------------------------------------------------
if ($method === 'POST') {
    if (!SoarAuth::hasPermission($auth['tier'], 'create_incidents')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => 'Tier 1 analysts cannot trigger risk recalculation. Requires Tier 2 or higher.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $rawInput = file_get_contents('php://input');
    $body = json_decode($rawInput, true) ?: $_POST;

    // Defense against direct client score tampering
    if (isset($body['risk_score']) || isset($body['score']) || isset($body['priority'])) {
        http_response_code(422);
        echo json_encode([
            'success' => false,
            'error'   => 'tampering_detected',
            'message' => 'Direct manual assignment of risk_score or priority is forbidden. Scores are calculated deterministically by server policy.'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $incidentId = isset($body['incident_id']) && is_numeric($body['incident_id']) 
        ? (int)$body['incident_id'] 
        : (isset($body['id']) && is_numeric($body['id']) ? (int)$body['id'] : null);

    if (!$incidentId) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'missing_incident_id', 'message' => 'Parameter incident_id is required.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    try {
        $assessment = $engine->recalculateIncident($incidentId, $auth['actor']);

        echo json_encode([
            'success'    => true,
            'action'     => 'recalculated',
            'assessment' => $assessment->toArray()
        ], JSON_UNESCAPED_SLASHES);
        exit;

    } catch (InvalidArgumentException $e) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'not_found', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
        exit;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Risk recalculation failed.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

http_response_code(405);
header('Allow: GET, POST');
echo json_encode(['success' => false, 'error' => 'method_not_allowed'], JSON_UNESCAPED_SLASHES);
exit;
