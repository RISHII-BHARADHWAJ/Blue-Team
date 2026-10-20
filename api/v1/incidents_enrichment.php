<?php
/**
 * ThreatPulse SOAR - Incident Threat Intelligence Enrichment Trigger API Endpoint
 * 
 * Endpoint: POST /api/v1/incidents_enrichment.php
 * 
 * Accepts:
 * {
 *   "incident_id": 123
 * }
 * 
 * Executes:
 * 1. IOC extraction from incident telemetry
 * 2. Deduplicated IOC upsert & role contextualization
 * 3. Multi-provider TI enrichment lookup & caching
 * 4. Audit logging
 * 
 * Security:
 * - Session or Bearer authentication
 * - Tier 2+ authorization required
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/SoarCsrf.php';
require_once __DIR__ . '/../../includes/soar/IncidentIocService.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized', 'message' => 'Authentication required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    echo json_encode(['success' => false, 'error' => 'method_not_allowed'], JSON_UNESCAPED_SLASHES);
    exit;
}

SoarCsrf::enforce($auth);

if (!SoarAuth::hasPermission($auth['tier'], 'create_incidents')) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => 'Tier 1 analysts cannot trigger incident enrichment. Requires Tier 2 or higher.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$rawInput = file_get_contents('php://input');
$body = json_decode($rawInput, true) ?: $_POST;

$incidentId = isset($body['incident_id']) && is_numeric($body['incident_id']) 
    ? (int)$body['incident_id'] 
    : (isset($body['id']) && is_numeric($body['id']) ? (int)$body['id'] : null);

if (!$incidentId) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'missing_incident_id', 'message' => 'Parameter incident_id is required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

try {
    $service = new IncidentIocService($pdo);
    $result = $service->processIncidentIocs($incidentId, true, $auth['actor']);

    echo json_encode([
        'success' => true,
        'action'  => 'incident_enriched',
        'data'    => $result
    ], JSON_UNESCAPED_SLASHES);
    exit;

} catch (InvalidArgumentException $e) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'not_found', 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
    exit;
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to execute incident threat intelligence enrichment.'], JSON_UNESCAPED_SLASHES);
    exit;
}
