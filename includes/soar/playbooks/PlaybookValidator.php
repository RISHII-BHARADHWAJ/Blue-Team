<?php
/**
 * ThreatPulse SOAR - Playbook Validator
 *
 * Validates a playbook definition and its steps before persistence or execution.
 * All constraints are enforced in trusted application code — never relaxed by DB input.
 */

require_once __DIR__ . '/ActionRegistry.php';
require_once __DIR__ . '/TemplateResolver.php';

class PlaybookValidator {

    public const MAX_STEPS          = 25;
    public const MAX_TIMEOUT        = 300;
    public const MAX_RETRIES        = 2;

    public const VALID_TRIGGER_TYPES  = ['AUTOMATIC', 'MANUAL', 'SCHEDULED'];
    public const VALID_CATEGORIES     = ['CONTAINMENT','ENRICHMENT','INVESTIGATION','REMEDIATION','NOTIFICATION'];
    public const VALID_APPROVAL_TIERS = ['TIER1','TIER2','LEAD','ADMIN'];

    // Shell / code-injection metacharacter pattern for identifier fields
    private const DANGEROUS_PATTERN = '/[;\(\)\[\]\$`\'\"\\\\|&<>{}!]/';

    private ActionRegistry  $registry;
    private TemplateResolver $resolver;

    public function __construct(?PDO $pdo = null) {
        $this->registry = new ActionRegistry($pdo);
        $this->resolver  = new TemplateResolver();
    }

    /**
     * Validate a complete playbook definition array.
     * @return string[] list of validation error messages (empty = valid)
     */
    public function validate(array $playbook, array $steps = []): array {
        $errors = [];

        // ---- Playbook-level fields ------------------------------------------
        if (empty(trim($playbook['playbook_name'] ?? ''))) {
            $errors[] = 'playbook_name is required.';
        } elseif (preg_match(self::DANGEROUS_PATTERN, $playbook['playbook_name'])) {
            $errors[] = 'playbook_name contains forbidden characters.';
        }

        if (empty(trim($playbook['display_name'] ?? ''))) {
            $errors[] = 'display_name is required.';
        }

        if (!empty($playbook['trigger_type']) && !in_array(strtoupper($playbook['trigger_type']), self::VALID_TRIGGER_TYPES, true)) {
            $errors[] = "trigger_type must be one of: " . implode(', ', self::VALID_TRIGGER_TYPES);
        }

        if (!empty($playbook['category']) && !in_array(strtoupper($playbook['category']), self::VALID_CATEGORIES, true)) {
            $errors[] = "category must be one of: " . implode(', ', self::VALID_CATEGORIES);
        }

        if (!empty($playbook['min_approval_tier']) && !in_array(strtoupper($playbook['min_approval_tier']), self::VALID_APPROVAL_TIERS, true)) {
            $errors[] = "min_approval_tier must be one of: " . implode(', ', self::VALID_APPROVAL_TIERS);
        }

        // ---- Steps validation -----------------------------------------------
        if (!empty($steps)) {
            if (count($steps) > self::MAX_STEPS) {
                $errors[] = "Playbook exceeds maximum of " . self::MAX_STEPS . " steps (" . count($steps) . " given).";
            }

            $stepOrders = [];
            $stepIds    = array_column($steps, 'id');

            foreach ($steps as $idx => $step) {
                $prefix = "Step #{$idx}";

                // Action type must be in allowlist
                $actionType = strtoupper(trim($step['action_type'] ?? ''));
                if (!$this->registry->isAllowed($actionType)) {
                    $errors[] = "{$prefix}: action_type '{$actionType}' is not in the registered allowlist.";
                }

                // Step name must not contain dangerous characters
                if (!empty($step['step_name']) && preg_match(self::DANGEROUS_PATTERN, $step['step_name'])) {
                    $errors[] = "{$prefix}: step_name contains forbidden characters.";
                }

                // Timeout
                $timeout = (int)($step['timeout_seconds'] ?? 60);
                if ($timeout < 0) {
                    $errors[] = "{$prefix}: timeout_seconds cannot be negative.";
                }
                if ($timeout > self::MAX_TIMEOUT) {
                    $errors[] = "{$prefix}: timeout_seconds ({$timeout}) exceeds maximum of " . self::MAX_TIMEOUT . "s.";
                }

                // Retries (if field exists)
                if (isset($step['max_retries'])) {
                    $retries = (int)$step['max_retries'];
                    if ($retries < 0) {
                        $errors[] = "{$prefix}: max_retries cannot be negative.";
                    }
                    if ($retries > self::MAX_RETRIES) {
                        $errors[] = "{$prefix}: max_retries ({$retries}) exceeds maximum of " . self::MAX_RETRIES . ".";
                    }
                }

                // Step order uniqueness
                $order = (int)($step['step_order'] ?? 0);
                if (in_array($order, $stepOrders, true)) {
                    $errors[] = "{$prefix}: duplicate step_order {$order}.";
                }
                $stepOrders[] = $order;

                // Branch targets must reference existing step IDs
                foreach (['on_success_step', 'on_failure_step'] as $branch) {
                    if (!empty($step[$branch]) && !in_array((int)$step[$branch], $stepIds, true)) {
                        $errors[] = "{$prefix}: {$branch} references unknown step ID " . $step[$branch] . ".";
                    }
                }

                // Template validation in action_parameters
                if (!empty($step['action_parameters'])) {
                    $params = is_string($step['action_parameters'])
                        ? json_decode($step['action_parameters'], true) ?? []
                        : $step['action_parameters'];

                    $templateErrors = $this->resolver->validateParameterTemplates($params);
                    foreach ($templateErrors as $te) {
                        $errors[] = "{$prefix} parameter template error: {$te}";
                    }
                }
            }
        }

        return $errors;
    }

    /**
     * Convenience: throw on first error.
     */
    public function assertValid(array $playbook, array $steps = []): void {
        $errors = $this->validate($playbook, $steps);
        if (!empty($errors)) {
            throw new RuntimeException("Playbook validation failed: " . implode('; ', $errors));
        }
    }
}
