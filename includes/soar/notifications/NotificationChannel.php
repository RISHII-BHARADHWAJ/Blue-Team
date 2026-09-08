<?php
/**
 * ThreatPulse SOAR - Notification Channel Interface
 *
 * Defines the contract for dispatching notifications to analysts across
 * various communication channels (In-App, future Webhook, future Email/Slack).
 */
interface NotificationChannel {
    /**
     * Send a notification through this channel.
     *
     * @param int    $userId    Target user ID
     * @param string $type      Standardized notification event type
     * @param string $title     Brief summary / notification title
     * @param string $message   Sanitized notification message body
     * @param array  $context   Contextual IDs ['incident_id' => ..., 'approval_id' => ..., 'playbook_run_id' => ...]
     * @return bool True if dispatch succeeded
     */
    public function send(int $userId, string $type, string $title, string $message, array $context = []): bool;
}
