<?php
/**
 * ThreatPulse SOAR - Authorization & Permission Resolver
 * 
 * Maps existing application roles ('admin', 'analyst', 'user') to SOAR
 * tier permissions (TIER1, TIER2, LEAD, ADMIN) without altering the users table schema.
 * 
 * Permissions Hierarchy:
 * - TIER1 (Junior Analyst): View incidents, view alerts, add case notes.
 * - TIER2 (Senior Analyst): Create incidents, attach alerts, assign cases, change status within workflow.
 * - LEAD  (SOC Lead / Manager): All Tier 2 + close incidents, override status, approve containment actions.
 * - ADMIN (Administrator): All permissions + system configuration.
 */

class SoarAuth {

    public const TIER_1     = 'TIER1';
    public const TIER_2     = 'TIER2';
    public const LEAD       = 'LEAD';
    public const ADMIN      = 'ADMIN';
    public const TIER_LEAD  = self::LEAD;
    public const TIER_ADMIN = self::ADMIN;

    /**
     * Map existing database `users.role` strings to SOAR permission tiers.
     */
    public static function resolveTier(?string $dbRole): string {
        if ($dbRole === null) {
            return self::TIER_1;
        }

        $normalized = strtolower(trim($dbRole));

        return match ($normalized) {
            'admin', 'administrator', 'root' => self::ADMIN,
            'lead', 'soc_lead', 'manager'    => self::LEAD,
            'analyst', 'senior_analyst'      => self::TIER_2,
            default                          => self::TIER_1,
        };
    }

    /**
     * Check if a given tier has a specific capability.
     */
    public static function hasPermission(string $tier, string $capability): bool {
        $permissions = [
            // Read capabilities — all authenticated tiers
            'view_incidents'       => [self::TIER_1, self::TIER_2, self::LEAD, self::ADMIN],
            'view_alerts'          => [self::TIER_1, self::TIER_2, self::LEAD, self::ADMIN],
            'add_notes'            => [self::TIER_1, self::TIER_2, self::LEAD, self::ADMIN],

            // Analyst-level write capabilities (Tier 2+)
            'create_incidents'     => [self::TIER_2, self::LEAD, self::ADMIN],
            'attach_alerts'        => [self::TIER_2, self::LEAD, self::ADMIN],
            'manual_escalate'      => [self::TIER_2, self::LEAD, self::ADMIN],
            'assign_incidents'     => [self::TIER_2, self::LEAD, self::ADMIN],
            'change_status_normal' => [self::TIER_2, self::LEAD, self::ADMIN],

            // SOAR Playbook execution (Tier 2+ can run; Tier 1 forced to DRY_RUN by API layer)
            'execute_playbooks'    => [self::TIER_2, self::LEAD, self::ADMIN],

            // SOC Lead / Admin capabilities
            'close_incidents'      => [self::LEAD, self::ADMIN],
            'change_severity'      => [self::LEAD, self::ADMIN],

            // SOAR approval gate: only LEAD and ADMIN may approve gated actions
            'approve_actions'      => [self::LEAD, self::ADMIN],

            // Admin-only capabilities
            'admin_operations'     => [self::ADMIN],

            // SOAR playbook definition management: Admin-only
            'manage_playbooks'     => [self::ADMIN],
        ];

        if (!isset($permissions[$capability])) {
            return false;
        }

        return in_array($tier, $permissions[$capability], true);
    }

    /**
     * Return the numeric tier rank for hierarchy comparisons.
     * Higher = more privileged.
     */
    private static function tierRank(string $tier): int {
        return match ($tier) {
            self::ADMIN  => 4,
            self::LEAD   => 3,
            self::TIER_2 => 2,
            self::TIER_1 => 1,
            default      => 0,
        };
    }

    /**
     * Check whether $actualTier satisfies the $requiredTier minimum.
     *
     * Example: meetsMinimumTier('ADMIN', 'LEAD') === true
     *          meetsMinimumTier('TIER1', 'LEAD') === false
     */
    public static function meetsMinimumTier(string $actualTier, string $requiredTier): bool {
        return self::tierRank($actualTier) >= self::tierRank($requiredTier);
    }

    /**
     * Resolve the current actor and tier from the active session or API token context.
     * 
     * @param ?PDO $pdo Database connection
     * @return array ['actor' => string, 'user_id' => ?int, 'tier' => string, 'role' => string, 'auth_method' => string]
     */
    public static function getContext(?PDO $pdo = null): array {
        if (session_status() === PHP_SESSION_NONE) {
            session_name('CYBERTECH_SECURE_SESSION');
            @session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict', 'use_strict_mode' => true]);
        }

        // 1. Session Context
        if (!empty($_SESSION['analyst']) || !empty($_SESSION['username']) || !empty($_SESSION['user_id'])) {
            $username = $_SESSION['analyst'] ?? ($_SESSION['username'] ?? 'user_' . $_SESSION['user_id']);
            $userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
            $role = $_SESSION['role'] ?? 'analyst';
            $tier = self::resolveTier($role);

            return [
                'actor'   => $username,
                'auth_method' => 'session',
                'user_id' => $userId,
                'tier'    => $tier,
                'role'    => $role
            ];
        }

        // 2. API Bearer Context
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/^Bearer\s+([a-zA-Z0-9_\-\.]{16,128})$/i', trim($authHeader), $matches)) {
            // Resolve system API key strictly from the environment. No hardcoded
            // fallback: if THREATPULSE_API_KEY isn't configured, bearer-token
            // auth must not succeed against a known default secret — treat the
            // request as unauthenticated instead.
            $configuredKey = getenv('THREATPULSE_API_KEY');
            if ($configuredKey !== false && $configuredKey !== '' &&
                hash_equals(hash('sha256', $configuredKey), hash('sha256', $matches[1]))) {
                return [
                    'actor'   => 'api_automation',
                    'auth_method' => 'bearer',
                    'user_id' => null,
                    'tier'    => self::TIER_2, // API sensors have Tier 2 ingestion/correlation rights
                    'role'    => 'analyst'
                ];
            }
        }

        // Default Unauthenticated
        return [
            'actor'   => 'anonymous',
            'auth_method' => 'anonymous',
            'user_id' => null,
            'tier'    => self::TIER_1,
            'role'    => 'guest'
        ];
    }
}