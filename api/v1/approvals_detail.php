<?php
/**
 * ThreatPulse SOAR - Approval Detail REST API Endpoint
 *
 * Endpoint: /api/v1/approvals_detail.php?id=123
 *
 * Methods Supported:
 * - GET: Retrieve comprehensive, read-only approval context including:
 *   - Incident metadata (severity, priority, risk score)
 *   - Correlated alerts and IOC evidence
 *   - Phase 5 explainable risk factor breakdown
 *   - Action preview with sensitive secrets strictly redacted
 *   - Audit view milestone (without state mutation)
 *
 * Security:
 * - Server-side authentication (SoarAuth::getContext)
 * - Permission enforcement ('view_incidents' - Tier 1+)
 * - IDOR protection: access validated against authoritative DB records
 * - Rate limiting
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth_check.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/approvals/ApprovalService.php';

// 1. Authenticate Request
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error'   => 'unauthorized',
        'message' => 'Authentication required.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    echo json_encode(['success' => false, 'error' => 'method_not_allowed']);
    exit;
}

// 2. Authorize
if (!SoarAuth::hasPermission($auth['tier'], 'view_incidents')) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => 'Insufficient permissions to view approval details.']);
    exit;
}

$approvalId = isset($_GET['id']) && is_numeric($_GET['id']) ? (int)$_GET['id'] : null;
if (!$approvalId) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'missing_id', 'message' => 'Query parameter ?id= (integer) is required.']);
    exit;
}

// Rate Limiter
if (class_exists('RateLimiter') && $pdo) {
    try {
        RateLimiter::check('approvals_detail', 150, 60);
    } catch (Throwable $e) {}
}

try {
    $service = new ApprovalService($pdo);
    $detail  = $service->getApprovalDetail($approvalId, $auth);

    echo json_encode([
        'success' => true,
        'data'    => $detail,
    ], JSON_UNESCAPED_SLASHES);

} catch (InvalidArgumentException $e) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'not_found', 'message' => $e->getMessage()]);
} catch (RuntimeException $e) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => $e->getMessage()]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to load approval detail.']);
}
