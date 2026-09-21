<?php
/**
 * ThreatPulse SOAR - Notifications REST API Endpoint
 *
 * Endpoint: /api/v1/notifications.php
 *
 * Methods Supported:
 * - GET:  List in-app notifications for authenticated user, with unread count
 * - POST: Mark notification as read (with strict IDOR protection)
 *
 * Security:
 * - Server-side authentication via session or Bearer token (SoarAuth::getContext)
 * - IDOR Protection: analysts can only query or mark their own notifications (ADMIN override)
 * - CSRF verification on state-changing POST requests
 * - Rate limiting
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/security.php';
require_once __DIR__ . '/../../includes/auth_check.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/notifications/NotificationService.php';

// 1. Authenticate Request
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized', 'message' => 'Authentication required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$service = new NotificationService($pdo);
$currentUserId = (int)($auth['user_id'] ?? 1);

// -----------------------------------------------------------------------------
// GET: Retrieve User Notifications & Unread Count
// -----------------------------------------------------------------------------
if ($method === 'GET') {
    // IDOR Protection: Target user ID defaults to current authenticated user
    $targetUserId = isset($_GET['user_id']) && is_numeric($_GET['user_id']) ? (int)$_GET['user_id'] : $currentUserId;

    if ($targetUserId !== $currentUserId && $auth['tier'] !== SoarAuth::ADMIN) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'forbidden', 'message' => 'IDOR Violation: You cannot view notifications belonging to another user.']);
        exit;
    }

    $unreadOnly = !empty($_GET['unread_only']);
    $limit = isset($_GET['limit']) && is_numeric($_GET['limit']) ? max(1, min(100, (int)$_GET['limit'])) : 50;

    try {
        $notifications = $service->getUserNotifications($targetUserId, $auth, $unreadOnly, $limit);
        $unreadCount   = $service->getUnreadCount($targetUserId);

        echo json_encode([
            'success'      => true,
            'user_id'      => $targetUserId,
            'unread_count' => $unreadCount,
            'count'        => count($notifications),
            'data'         => $notifications,
        ], JSON_UNESCAPED_SLASHES);

    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => $e->getMessage()]);
    }
    exit;
}

// -----------------------------------------------------------------------------
// POST: Mark Notification as Read
// -----------------------------------------------------------------------------
if ($method === 'POST') {
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
    $body = json_decode($rawInput, true) ?: $_POST;

    $notificationId = isset($body['notification_id']) && is_numeric($body['notification_id']) ? (int)$body['notification_id'] : null;
    if (!$notificationId) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'missing_notification_id', 'message' => "Field 'notification_id' is required."]);
        exit;
    }

    try {
        // Enforce ownership inside markAsRead (WHERE id = ? AND (user_id = ? OR recipient_id = ?))
        $updated = $service->markAsRead($notificationId, $currentUserId);
        if (!$updated && $pdo) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'not_found', 'message' => "Notification #{$notificationId} not found or access denied."]);
            exit;
        }

        echo json_encode([
            'success'         => true,
            'notification_id' => $notificationId,
            'is_read'         => true,
            'unread_count'    => $service->getUnreadCount($currentUserId),
        ], JSON_UNESCAPED_SLASHES);

    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to mark notification as read.']);
    }
    exit;
}

http_response_code(405);
header('Allow: GET, POST');
echo json_encode(['success' => false, 'error' => 'method_not_allowed']);
