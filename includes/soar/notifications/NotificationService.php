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

    /** The recipient column predates user_id and is authoritative for legacy rows too. */
    public function resolveUserId(array $authContext): int {
        $id = filter_var($authContext['user_id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
        if (($authContext['auth_method'] ?? '') !== 'session' || !$id) {
            throw new DomainException('Sign in with a named user account to access a personal inbox.');
        }
        if ($this->pdo) {
            $stmt = $this->pdo->prepare('SELECT role FROM users WHERE id = ?');
            $stmt->execute([$id]); $role = $stmt->fetchColumn();
            if ($role === false || !SoarAuth::hasPermission(SoarAuth::resolveTier($role), 'view_incidents')) {
                throw new DomainException('The signed-in user account is unavailable.');
            }
        }
        return $id;
    }

    /** Compatibility method for the control-plane dropdown, restricted to the session owner. */
    public function getUserNotifications(int $userId, array $authContext, bool $unreadOnly = false, int $limit = 50): array {
        if ($this->resolveUserId($authContext) !== $userId) throw new DomainException('Personal inboxes cannot be accessed on behalf of another user.');
        return $this->inbox($authContext, $unreadOnly ? 'unread' : 'all', 1, $limit)['notifications'];
    }

    public function inbox(array $authContext, string $filter = 'unread', int $page = 1, int $limit = 25): array {
        $userId = $this->resolveUserId($authContext);
        if (!in_array($filter, ['all','unread','read'], true)) throw new InvalidArgumentException('Choose all, unread or read notifications.');
        $limit = max(1, min(100, $limit));
        $where = 'n.recipient_id = ?';
        if ($filter !== 'all') $where .= $filter === 'read' ? ' AND n.is_read = 1' : ' AND n.is_read = 0';
        $rows=[]; $total=0; $unread=0;
        if ($this->pdo) {
            $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM notifications n WHERE '.$where);
            $stmt->execute([$userId]); $total=(int)$stmt->fetchColumn();
            $unread=$this->getUnreadCount($userId);
        }
        $pages=max(1,(int)ceil($total/$limit)); $page=max(1,min($page,$pages));
        if ($this->pdo) {
            $stmt=$this->pdo->prepare("SELECT n.id, n.recipient_id AS user_id,
                CASE WHEN n.type='APPROVAL_REQUIRED' AND n.notification_type<>'APPROVAL_REQUIRED' THEN n.notification_type ELSE n.type END AS type,
                n.title, n.message, n.is_read, n.read_at, n.created_at,
                i.id AS incident_id, i.incident_number, i.is_simulated,
                r.id AS playbook_run_id, a.id AS approval_id
                FROM notifications n LEFT JOIN incidents i ON i.id=n.incident_id
                LEFT JOIN playbook_runs r ON r.id=n.playbook_run_id AND r.incident_id=i.id
                LEFT JOIN approval_requests a ON a.id=n.approval_id AND a.incident_id=i.id
                    AND EXISTS (SELECT 1 FROM playbook_runs ar WHERE ar.id=a.playbook_run_id AND ar.incident_id=i.id)
                WHERE ".$where.' ORDER BY n.created_at DESC,n.id DESC LIMIT ? OFFSET ?');
            $stmt->bindValue(1,$userId,PDO::PARAM_INT); $stmt->bindValue(2,$limit,PDO::PARAM_INT);
            $stmt->bindValue(3,($page-1)*$limit,PDO::PARAM_INT); $stmt->execute(); $rows=$stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$row) {
                $row['title']=$this->redactSecrets($row['title']);
                $row['message']=$this->redactSecrets($row['message']);
            }
            unset($row);
        }
        return ['user_id'=>$userId,'notifications'=>$rows,'unread_count'=>$unread,'filter'=>$filter,
            'pagination'=>['total'=>$total,'page'=>$page,'pages'=>$pages,'per_page'=>$limit]];
    }

    /** Idempotent acknowledgement: retain the original read timestamp on retries. */
    public function markAsRead(int $notificationId, int $userId): bool {
        if ($notificationId < 1 || $userId < 1) return false;
        if (!$this->pdo) return true;
        $stmt=$this->pdo->prepare('UPDATE notifications SET is_read=1, read_at=COALESCE(read_at,NOW())
            WHERE id=? AND recipient_id=? AND is_read=0');
        $stmt->execute([$notificationId,$userId]);
        if ($stmt->rowCount()>0) return true;
        $stmt=$this->pdo->prepare('SELECT 1 FROM notifications WHERE id=? AND recipient_id=?');
        $stmt->execute([$notificationId,$userId]); return (bool)$stmt->fetchColumn();
    }

    /** Only submitted IDs are acknowledged; later arrivals are never swept into a bulk action. */
    public function markReadBatch(array $notificationIds, array $authContext): int {
        if (!$notificationIds || count($notificationIds)>25) throw new InvalidArgumentException('Select between 1 and 25 notifications.');
        $ids=[];
        foreach ($notificationIds as $id) {
            $valid=filter_var($id,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
            if (!$valid) throw new InvalidArgumentException('Notification IDs must be positive integers.');
            $ids[$valid]=$valid;
        }
        sort($ids,SORT_NUMERIC);
        $userId=$this->resolveUserId($authContext);
        if (!$this->pdo) return count($ids);
        $own=!$this->pdo->inTransaction(); $sp='inbox_'.bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $sp");
        try {
            $placeholders=implode(',',array_fill(0,count($ids),'?'));
            $stmt=$this->pdo->prepare('SELECT id,is_read FROM notifications WHERE recipient_id=? AND id IN ('.$placeholders.') ORDER BY id FOR UPDATE');
            $stmt->execute(array_merge([$userId],$ids)); $rows=$stmt->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows)!==count($ids)) throw new OutOfBoundsException('One or more notifications are unavailable in your inbox. Nothing was changed.');
            $changed=0;
            foreach ($rows as $row) {
                if (!$row['is_read']) { $this->markAsRead((int)$row['id'],$userId); $changed++; }
            }
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $sp");
            return $changed;
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $sp"); $this->pdo->exec("RELEASE SAVEPOINT $sp"); }
            }
            throw $e;
        }
    }

    public function getUnreadCount(int $userId): int {
        if (!$this->pdo || $userId<1) return 0;
        $stmt=$this->pdo->prepare('SELECT COUNT(*) FROM notifications WHERE recipient_id=? AND is_read=0');
        $stmt->execute([$userId]); return (int)$stmt->fetchColumn();
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
