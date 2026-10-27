<?php
/**
 * ThreatPulse SOAR - Approval Requests REST API Endpoint
 *
 * Endpoint: /api/v1/approvals.php
 *
 * Methods Supported:
 * - GET:  List approvals with filtering, priority sorting, and pagination (Tier 1+)
 * - POST: Process atomic approval or rejection decision (LEAD / ADMIN)
 *
 * Security:
 * - Server-side authentication via session or Bearer token (SoarAuth::getContext)
 * - Strict capability checks ('view_incidents' for GET, 'approve_actions' for POST)
 * - Rate limiting via RateLimiter
 * - Anti-tampering: direct injection of security attributes rejected with HTTP 422
 * - CSRF verification for session-authenticated POST decisions
 * - Strict 15-step transactional state transition order
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/security.php';
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
        'message' => 'Authentication required to access approvals control plane.'
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$service = new ApprovalService($pdo);

// -----------------------------------------------------------------------------
// GET: List Approval Requests
// -----------------------------------------------------------------------------
if ($method === 'GET') {
    if (!SoarAuth::hasPermission($auth['tier'], 'view_incidents')) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'error'   => 'forbidden',
            'message' => 'Insufficient permissions to view approval requests.'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Rate Limiter
    if (class_exists('RateLimiter') && $pdo) {
        try {
            RateLimiter::check('approvals_list', 120, 60);
        } catch (Throwable $e) {}
    }

    $filters = [
        'status'         => !empty($_GET['status']) ? strtoupper(trim($_GET['status'])) : null,
        'priority'       => !empty($_GET['priority']) ? strtoupper(trim($_GET['priority'])) : null,
        'incident_id'    => isset($_GET['incident_id']) && is_numeric($_GET['incident_id']) ? (int)$_GET['incident_id'] : null,
        'created_after'  => !empty($_GET['created_after']) ? trim($_GET['created_after']) : null,
        'created_before' => !empty($_GET['created_before']) ? trim($_GET['created_before']) : null,
    ];

    $limit  = isset($_GET['limit']) && is_numeric($_GET['limit']) ? max(1, min(100, (int)$_GET['limit'])) : 50;
    $offset = isset($_GET['offset']) && is_numeric($_GET['offset']) ? max(0, (int)$_GET['offset']) : 0;

    try {
        $approvals = $service->listApprovals($filters, $auth, $limit, $offset);
        echo json_encode([
            'success' => true,
            'count'   => count($approvals),
            'filters' => array_filter($filters, fn($v) => $v !== null),
            'data'    => $approvals,
        ], JSON_UNESCAPED_SLASHES);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Could not retrieve approvals.']);
    }
    exit;
}

// -----------------------------------------------------------------------------
// POST: Process Approval Decision (APPROVE / REJECT)
// -----------------------------------------------------------------------------
if ($method === 'POST') {
    // Check permission early
    if (!SoarAuth::hasPermission($auth['tier'], 'approve_actions')) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'error'   => 'forbidden',
            'message' => 'Authorization denied: Tier lacks approve_actions capability.'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Rate Limiter
    if (class_exists('RateLimiter') && $pdo) {
        try {
            RateLimiter::check('approvals_decision', 30, 60);
        } catch (Throwable $e) {}
    }

    // CSRF Check for session users
    if ($auth['actor'] !== 'api_automation') {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? null);
        if (!$csrfToken || !verifyCSRFToken($csrfToken)) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'csrf_verification_failed', 'message' => 'Invalid or missing CSRF token.']);
            exit;
        }
    }

    $rawInput = file_get_contents('php://input');
    $body = json_decode($rawInput, true);
    if (!is_array($body)) {
        $body = $_POST;
    }

    // Anti-Tampering Check: reject any client attempt to supply server-side authoritative state
    $validator = new ApprovalValidator();
    try {
        $validator->assertNoClientTampering($body);
    } catch (InvalidArgumentException $e) {
        http_response_code(422);
        echo json_encode(['success' => false, 'error' => 'tampering_detected', 'message' => $e->getMessage()]);
        exit;
    }

    $approvalId = isset($body['approval_id']) && is_numeric($body['approval_id']) ? (int)$body['approval_id'] : null;
    $decision   = isset($body['decision']) ? strtoupper(trim((string)$body['decision'])) : null;
    $reason     = isset($body['reason']) ? trim((string)$body['reason']) : null;

    if (!$approvalId || !in_array($decision, ['APPROVE', 'REJECT'], true)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error'   => 'invalid_request',
            'message' => "Parameters 'approval_id' (integer) and 'decision' ('APPROVE' or 'REJECT') are required."
        ]);
        exit;
    }

    try {
        $decisionObj = new ApprovalDecision(
            $approvalId,
            $decision,
            $reason,
            (int)($auth['user_id'] ?? 1),
            $auth['tier']
        );

        $result = $service->processDecision($decisionObj, $auth);
        echo json_encode([
            'success' => true,
            'data'    => $result,
        ], JSON_UNESCAPED_SLASHES);

    } catch (InvalidArgumentException $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'bad_request', 'message' => $e->getMessage()]);
    } catch (RuntimeException $e) {
        // Distinguish authorization vs concurrency/conflict vs expiration
        $msg = $e->getMessage();
        if (str_contains($msg, 'Authorization denied') || str_contains($msg, 'Unauthorized')) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => $msg]);
        } elseif (str_contains($msg, 'expired')) {
            http_response_code(410); // Gone / Expired
            echo json_encode(['success' => false, 'error' => 'approval_expired', 'message' => $msg]);
        } elseif (str_contains($msg, 'already decided') || str_contains($msg, 'race condition') || str_contains($msg, 'could not be consumed')) {
            http_response_code(409); // Conflict
            echo json_encode(['success' => false, 'error' => 'conflict', 'message' => $msg]);
        } elseif (str_contains($msg, 'integrity')) {
            http_response_code(422); // Unprocessable Entity
            echo json_encode(['success' => false, 'error' => 'integrity_violation', 'message' => $msg]);
        } else {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'execution_failed', 'message' => $msg]);
        }
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Internal error during approval processing.']);
    }
    exit;
}

http_response_code(405);
header('Allow: GET, POST');
echo json_encode(['success' => false, 'error' => 'method_not_allowed']);
