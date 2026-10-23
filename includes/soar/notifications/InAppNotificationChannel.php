<?php
/**
 * ThreatPulse SOAR - In-App Notification Channel
 *
 * Persists notifications directly into the `notifications` database table.
 * Strictly escapes and sanitizes all inputs; never exposes credentials or secrets.
 */

require_once __DIR__ . '/NotificationChannel.php';

class InAppNotificationChannel implements NotificationChannel {
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
    }

    public function send(int $userId, string $type, string $title, string $message, array $context = []): bool {
        if (!$this->pdo) {
            return true; // Test mode simulation
        }

        try {
            $incidentId    = isset($context['incident_id']) ? (int)$context['incident_id'] : null;
            $approvalId    = isset($context['approval_id']) ? (int)$context['approval_id'] : null;
            $legacyType = $type === 'PLAYBOOK_FAILED' ? 'PLAYBOOK_FAILED' : (str_starts_with($type,'APPROVAL_') ? 'APPROVAL_REQUIRED' : 'INCIDENT_ASSIGNED');
            $playbookRunId = isset($context['playbook_run_id']) ? (int)$context['playbook_run_id'] : null;

            $stmt = $this->pdo->prepare("
                INSERT INTO notifications 
                    (user_id, recipient_id, type, notification_type, title, message, incident_id, approval_id, playbook_run_id, is_read, created_at)
                VALUES 
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NOW())
            ");
            return $stmt->execute([
                $userId,
                $userId,
                substr($type, 0, 50),
                $legacyType,
                substr($title, 0, 255),
                $message,
                $incidentId,
                $approvalId,
                $playbookRunId
            ]);
        } catch (Throwable $e) {
            error_log("InAppNotificationChannel error: " . $e->getMessage());
            return false;
        }
    }
}
