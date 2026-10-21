<?php
/** Read-only risk snapshots; explicit, authorized POST recalculates from server evidence. */
declare(strict_types=1);
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY'); header('Cache-Control: no-store');
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/SoarCsrf.php';
require_once __DIR__ . '/../../includes/soar/Risk/RiskScoringEngine.php';
function riskResponse(int $status, array $body): never { http_response_code($status); echo json_encode($body, JSON_UNESCAPED_SLASHES); exit; }
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') riskResponse(401, ['success'=>false, 'message'=>'Authentication required.']);
$method = $_SERVER['REQUEST_METHOD'];
if (!in_array($method, ['GET','POST'], true)) { header('Allow: GET, POST'); riskResponse(405, ['success'=>false, 'message'=>'Method not allowed.']); }
$body = $_GET;
if ($method === 'POST') {
    SoarCsrf::enforce($auth);
    if (!SoarAuth::hasPermission($auth['tier'], 'create_incidents') || ($auth['auth_method'] === 'session' && empty($auth['user_id']))) {
        riskResponse(403, ['success'=>false, 'message'=>'A named Tier 2 or higher account is required to recalculate risk.']);
    }
    $raw = file_get_contents('php://input', false, null, 0, 65537);
    if ($raw === false || strlen($raw) > 65536) riskResponse(413, ['success'=>false, 'message'=>'Request too large.']);
    if (str_starts_with(strtolower($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json')) {
        try { $body = json_decode($raw, true, 64, JSON_THROW_ON_ERROR); }
        catch (JsonException $e) { riskResponse(400, ['success'=>false, 'message'=>'Invalid JSON.']); }
    } else $body = $_POST;
    if (!is_array($body)) riskResponse(400, ['success'=>false, 'message'=>'Expected an object.']);
    foreach (['risk_score','score','priority','assetMetadata','asset_metadata','criticality'] as $field) {
        if (array_key_exists($field, $body)) riskResponse(422, ['success'=>false, 'message'=>'Scores, priority and asset context must come from server policy and evidence.']);
    }
}
$id = filter_var($body['incident_id'] ?? $body['id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
if (!$id) riskResponse(400, ['success'=>false, 'message'=>'A positive incident ID is required.']);
try {
    $engine = new RiskScoringEngine($pdo);
    if ($method === 'GET') {
        $page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;
        $data = $engine->workspace($id, $page);
        riskResponse(200, ['success'=>true, 'data'=>$data]);
    }
    $assessment = $engine->recalculateIncident($id, $auth['actor'], [], $auth['auth_method'] === 'session' ? (int)$auth['user_id'] : null);
    riskResponse(200, ['success'=>true, 'action'=>'recalculated', 'assessment'=>$assessment->toArray()]);
} catch (DomainException $e) { riskResponse(403, ['success'=>false, 'message'=>$e->getMessage()]); }
catch (InvalidArgumentException $e) { riskResponse(404, ['success'=>false, 'message'=>$e->getMessage()]); }
catch (Throwable $e) { error_log('Risk operation failed: ' . $e->getMessage()); riskResponse(500, ['success'=>false, 'message'=>'Risk operation failed. Check the case before retrying.']); }
