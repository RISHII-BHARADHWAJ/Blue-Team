<?php
/**
 * ThreatPulse SOAR - Notification Service
 *
 * Central service for emitting, querying, and managing in-app notifications.
 * Enforces IDOR protection, channel abstraction, and secret redaction.
 */

require_once __DIR__ . '/NotificationChannel.php';
require_once __DIR__ . '/InAppNotificationChannel.php';
require_once __DIR__ . '/../SoarAuth.php';

class NotificationService {
    public const TYPE_APPROVAL_REQUESTED = 'APPROVAL_REQUESTED';
    public const TYPE_APPROVAL_APPROVED  = 'APPROVAL_APPROVED';
    public const TYPE_APPROVAL_REJECTED  = 'APPROVAL_REJECTED';
    public const TYPE_APPROVAL_EXPIRED   = 'APPROVAL_EXPIRED';
    public const TYPE_PLAYBOOK_COMPLETED = 'PLAYBOOK_COMPLETED';
    public const TYPE_PLAYBOOK_FAILED    = 'PLAYBOOK_FAILED';

    private ?PDO $pdo;
    private array $channels = [];

    public function __construct(?PDO $pdo = null, array $customChannels = []) {
        $this->pdo = $pdo;
        if (!empty($customChannels)) {
            $this->channels = $customChannels;
        } else {
            $this->channels = [new InAppNotificationChannel($pdo)];
        }
    }

    /**
     * Dispatch a notification to a specific user across all registered channels.
     */
    public function notify(int $userId, string $type, string $title, string $message, array $context = []): bool {
        $sanitizedTitle   = $this->redactSecrets($title);
        $sanitizedMessage = $this->redactSecrets($message);

        $success = true;
        foreach ($this->channels as $channel) {
            if (!$channel->send($userId, $type, $sanitizedTitle, $sanitizedMessage, $context)) {
                $success = false;
            }
        }
        return $success;
    }

    /**
     * Broadcast a notification to all analysts meeting or exceeding a minimum tier.
     * E.g. notifyTier('LEAD', 'APPROVAL_REQUESTED', ...) alerts all Lead/Admin analysts.
     *
     * @return int Number of users notified
     */
    public function notifyTier(string $minTier, string $type, string $title, string $message, array $context = []): int {
        if (!$this->pdo) {
            return 1; // Test simulation count
        }

        try {
            $stmt = $this->pdo->query("SELECT id, role FROM users");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $count = 0;

            foreach ($users as $user) {
                $userTier = SoarAuth::resolveTier($user['role'] ?? '');
                if (SoarAuth::meetsMinimumTier($userTier, $minTier)) {
                    if ($this->notify((int)$user['id'], $type, $title, $message, $context)) {
                        $count++;
                    }
                }
            }
            return $count;
        } catch (Throwable $e) {
            error_log("NotificationService::notifyTier error: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Retrieve notifications for an authenticated user with IDOR protection.
     * Analysts can only view their own notifications unless they are ADMIN.
     */
    public function getUserNotifications(int $userId, array $authContext, bool $unreadOnly = false, int $limit = 50): array {
        // IDOR Authorization check
        $authUserId = (int)($authContext['user_id'] ?? 0);
        $authTier   = $authContext['tier'] ?? SoarAuth::TIER_1;

        if ($authUserId !== $userId && $authTier !== SoarAuth::ADMIN) {
            throw new RuntimeException("Unauthorized: Cannot access notifications belonging to another analyst.");
        }

        if (!$this->pdo) {
            return [];
        }

        $sql = "SELECT id, user_id, type, title, message, incident_id, approval_id, playbook_run_id, is_read, read_at, created_at 
                FROM notifications 
                WHERE (user_id = ? OR recipient_id = ?)";
        if ($unreadOnly) {
            $sql .= " AND is_read = 0";
        }
        $sql .= " ORDER BY created_at DESC, id DESC LIMIT " . max(1, min(100, $limit));

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$userId, $userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Mark a notification as read with ownership verification.
     */
    public function markAsRead(int $notificationId, int $userId): bool {
        if (!$this->pdo) {
            return true;
        }

        $stmt = $this->pdo->prepare("
            UPDATE notifications 
            SET is_read = 1, read_at = NOW() 
            WHERE id = ? AND (user_id = ? OR recipient_id = ?)
        ");
        $stmt->execute([$notificationId, $userId, $userId]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Get unread notification count for a user.
     */
    public function getUnreadCount(int $userId): int {
        if (!$this->pdo) {
            return 0;
        }

        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) FROM notifications 
            WHERE (user_id = ? OR recipient_id = ?) AND is_read = 0
        ");
        $stmt->execute([$userId, $userId]);
        return (int)$stmt->fetchColumn();
    }

    /**
     * Redact passwords, API keys, bearer tokens, and secrets from notification text.
     */
    public function redactSecrets(string $text): string {
        $patterns = [
            '/(?:password|passwd|pwd)[\s:=]+([^\s,;]+)/i'        => 'password: [REDACTED]',
            '/(?:bearer|api_key|secret|token)[\s:=]+([^\s,;]+)/i' => 'token: [REDACTED]',
            '/Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.]+/i'      => 'Authorization: Bearer [REDACTED]',
            '/\b[A-Fa-f0-9]{64}\b/'                              => '[HASH_REDACTED]',
        ];
        return preg_replace(array_keys($patterns), array_values($patterns), $text) ?? $text;
    }
}
