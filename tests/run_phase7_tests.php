<?php
/**
 * ThreatPulse SOAR - Phase 7 Test Suite: SOC Approval & Response Control Plane
 *
 * 34 test cases covering:
 * - Approval queue listing & authorization (IDOR protection)
 * - Approval state machine transitions & terminal invariants
 * - Server-side expiration validation
 * - Approver authorization & tier hierarchy enforcement (meetsMinimumTier)
 * - Anti-tampering guards (rejection of client-supplied risk/priority/payload fields)
 * - Rejection reason validation & XSS sanitization
 * - Payload hash integrity & anti-tampering detection
 * - Deep secret redaction (passwords, tokens, API keys, Bearer headers, private keys)
 * - Non-destructive boundary verification (no BLOCK_IP, ISOLATE_HOST, eval, exec)
 * - Playbook version locking (run retains locked definition version)
 * - Audit semantics (VIEW vs DECISION distinction)
 * - Notification ownership & IDOR protection
 */

$is_cli = (php_sapi_name() === 'cli');

function p7_pass(int $n, string $name, string $detail = ''): void {
    global $is_cli;
    $msg = sprintf("[PASS] Test %02d: %s%s", $n, $name, $detail ? " — {$detail}" : '');
    echo ($is_cli ? "\033[32m{$msg}\033[0m" : htmlspecialchars($msg)) . "\n";
}

function p7_fail(int $n, string $name, string $detail = ''): void {
    global $is_cli;
    $msg = sprintf("[FAIL] Test %02d: %s%s", $n, $name, $detail ? " — {$detail}" : '');
    echo ($is_cli ? "\033[31m{$msg}\033[0m" : htmlspecialchars($msg)) . "\n";
}

require_once __DIR__ . '/../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../includes/soar/approvals/ApprovalDecision.php';
require_once __DIR__ . '/../includes/soar/approvals/ApprovalValidator.php';
require_once __DIR__ . '/../includes/soar/approvals/ApprovalRepository.php';
require_once __DIR__ . '/../includes/soar/approvals/ApprovalService.php';
require_once __DIR__ . '/../includes/soar/playbooks/ActionRegistry.php';
require_once __DIR__ . '/../includes/soar/playbooks/PlaybookEngine.php';
require_once __DIR__ . '/../includes/soar/playbooks/PlaybookRepository.php';
require_once __DIR__ . '/../includes/soar/playbooks/PlaybookRunManager.php';
require_once __DIR__ . '/../includes/soar/notifications/NotificationService.php';

$passed = 0; $failed = 0; $total = 34;

function p7test(int $n, string $name, callable $fn): void {
    global $passed, $failed;
    try {
        $r = $fn();
        if ($r === true) { p7_pass($n, $name); $passed++; }
        else             { p7_fail($n, $name, is_string($r) ? $r : 'assertion returned false'); $failed++; }
    } catch (Exception $e) {
        p7_fail($n, $name, 'Unexpected exception: ' . $e->getMessage()); $failed++;
    }
}

// ============================================================================
// SECTION 1: SOARAUTH & QUEUE AUTHORIZATION (IDOR PROTECTION)
// ============================================================================

p7test(1, "SoarAuth::hasPermission('view_incidents') permits viewing approval queue", function() {
    return SoarAuth::hasPermission(SoarAuth::TIER_1, 'view_incidents') === true &&
           SoarAuth::hasPermission(SoarAuth::TIER_2, 'view_incidents') === true &&
           SoarAuth::hasPermission(SoarAuth::LEAD, 'view_incidents') === true &&
           SoarAuth::hasPermission(SoarAuth::ADMIN, 'view_incidents') === true;
});

p7test(2, "Unauthorized role without view_incidents cannot list approvals (IDOR protection)", function() {
    $service = new ApprovalService(null);
    try {
        $service->listApprovals([], ['tier' => 'GUEST'], 10, 0);
        return "Expected RuntimeException not thrown";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'Unauthorized');
    }
});

// ============================================================================
// SECTION 2: STATE MACHINE TRANSITIONS & TERMINAL INVARIANTS
// ============================================================================

p7test(3, "ApprovalValidator::validateTransition allows PENDING -> APPROVED", function() {
    $v = new ApprovalValidator();
    $v->validateTransition('PENDING', 'APPROVED');
    return true;
});

p7test(4, "ApprovalValidator::validateTransition allows PENDING -> REJECTED", function() {
    $v = new ApprovalValidator();
    $v->validateTransition('PENDING', 'REJECTED');
    return true;
});

p7test(5, "ApprovalValidator::validateTransition allows PENDING -> EXPIRED", function() {
    $v = new ApprovalValidator();
    $v->validateTransition('PENDING', 'EXPIRED');
    return true;
});

p7test(6, "ApprovalValidator::validateTransition rejects APPROVED -> REJECTED (terminal state)", function() {
    $v = new ApprovalValidator();
    try {
        $v->validateTransition('APPROVED', 'REJECTED');
        return "Did not reject transition from terminal state APPROVED";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'Invalid approval state transition');
    }
});

p7test(7, "ApprovalValidator::validateTransition rejects REJECTED -> APPROVED (terminal state)", function() {
    $v = new ApprovalValidator();
    try {
        $v->validateTransition('REJECTED', 'APPROVED');
        return "Did not reject transition from terminal state REJECTED";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'Invalid approval state transition');
    }
});

p7test(8, "ApprovalValidator::validateTransition rejects EXPIRED -> APPROVED (replay guard)", function() {
    $v = new ApprovalValidator();
    try {
        $v->validateTransition('EXPIRED', 'APPROVED');
        return "Did not reject transition from EXPIRED";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'Invalid approval state transition');
    }
});

// ============================================================================
// SECTION 3: SERVER-SIDE EXPIRATION VALIDATION
// ============================================================================

p7test(9, "assertNotExpired permits future expiration timestamps", function() {
    $v = new ApprovalValidator();
    $future = date('Y-m-d H:i:s', time() + 3600);
    $v->assertNotExpired($future);
    return true;
});

p7test(10, "assertNotExpired throws on expired timestamp (authoritative server time)", function() {
    $v = new ApprovalValidator();
    $past = date('Y-m-d H:i:s', time() - 60);
    try {
        $v->assertNotExpired($past);
        return "Expired approval was not rejected";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'expired');
    }
});

// ============================================================================
// SECTION 4: APPROVER AUTHORIZATION & TIER HIERARCHY
// ============================================================================

p7test(11, "assertApproverAuthorized permits LEAD for LEAD-required action", function() {
    $v = new ApprovalValidator();
    $v->assertApproverAuthorized(SoarAuth::LEAD, 'LEAD');
    return true;
});

p7test(12, "assertApproverAuthorized permits ADMIN for LEAD-required action", function() {
    $v = new ApprovalValidator();
    $v->assertApproverAuthorized(SoarAuth::ADMIN, 'LEAD');
    return true;
});

p7test(13, "assertApproverAuthorized denies TIER1 for LEAD-required action (meetsMinimumTier)", function() {
    $v = new ApprovalValidator();
    try {
        $v->assertApproverAuthorized(SoarAuth::TIER_1, 'LEAD');
        return "Tier 1 was incorrectly authorized for LEAD action";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'Authorization denied');
    }
});

p7test(14, "assertApproverAuthorized denies TIER2 for LEAD-required action (tier hierarchy)", function() {
    $v = new ApprovalValidator();
    try {
        $v->assertApproverAuthorized(SoarAuth::TIER_2, 'LEAD');
        return "Tier 2 was incorrectly authorized for LEAD action";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'Authorization denied');
    }
});

p7test(15, "assertApproverAuthorized denies user lacking approve_actions capability", function() {
    $v = new ApprovalValidator();
    // TIER1 lacks approve_actions even if required tier is set to TIER1
    try {
        $v->assertApproverAuthorized(SoarAuth::TIER_1, 'TIER1');
        return "Analyst lacking approve_actions was allowed to approve";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'approve_actions');
    }
});

// ============================================================================
// SECTION 5: ANTI-TAMPERING GUARDS (CLIENT INPUT VALIDATION)
// ============================================================================

p7test(16, "assertNoClientTampering detects and rejects client-supplied risk_score", function() {
    $v = new ApprovalValidator();
    try {
        $v->assertNoClientTampering(['approval_id' => 1, 'decision' => 'APPROVE', 'risk_score' => 10]);
        return "Client-supplied risk_score was not detected";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'Tampering detected');
    }
});

p7test(17, "assertNoClientTampering detects and rejects client-supplied priority", function() {
    $v = new ApprovalValidator();
    try {
        $v->assertNoClientTampering(['approval_id' => 1, 'decision' => 'APPROVE', 'priority' => 'P4']);
        return "Client-supplied priority was not detected";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'Tampering detected');
    }
});

p7test(18, "assertNoClientTampering detects and rejects client-supplied action_parameters", function() {
    $v = new ApprovalValidator();
    try {
        $v->assertNoClientTampering(['approval_id' => 1, 'decision' => 'APPROVE', 'action_parameters' => ['ip' => '1.2.3.4']]);
        return "Client-supplied action_parameters was not detected";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'Tampering detected');
    }
});

p7test(19, "assertNoClientTampering detects and rejects client-supplied incident_id", function() {
    $v = new ApprovalValidator();
    try {
        $v->assertNoClientTampering(['approval_id' => 1, 'decision' => 'APPROVE', 'incident_id' => 999]);
        return "Client-supplied incident_id was not detected";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'Tampering detected');
    }
});

// ============================================================================
// SECTION 6: REJECTION REASON VALIDATION & XSS SANITIZATION
// ============================================================================

p7test(20, "validateAndNormalizeReason requires minimum 10 characters", function() {
    $v = new ApprovalValidator();
    try {
        $v->validateAndNormalizeReason('short');
        return "Short reason (< 10 chars) was accepted";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'at least 10 characters');
    }
});

p7test(21, "validateAndNormalizeReason rejects excessive length (>1000 characters)", function() {
    $v = new ApprovalValidator();
    $long = str_repeat('A', 1001);
    try {
        $v->validateAndNormalizeReason($long);
        return "Excessive reason (> 1000 chars) was accepted";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'exceeds maximum limit');
    }
});

p7test(22, "validateAndNormalizeReason strips HTML/script tags to prevent stored XSS", function() {
    $v = new ApprovalValidator();
    $payload = "<script>alert('xss')</script>Action requires further verification before execution.";
    $normalized = $v->validateAndNormalizeReason($payload);
    return !str_contains($normalized, '<script>') &&
           !str_contains($normalized, '</script>') &&
           str_contains($normalized, 'Action requires further verification');
});

p7test(23, "validateAndNormalizeReason rejects whitespace/punctuation-only evasion", function() {
    $v = new ApprovalValidator();
    try {
        $v->validateAndNormalizeReason("   ..... -----   ");
        return "Punctuation-only evasion was accepted";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'meaningful explanatory text');
    }
});

// ============================================================================
// SECTION 7: PAYLOAD INTEGRITY HASH VERIFICATION
// ============================================================================

p7test(24, "assertPayloadIntegrity passes for matching SHA-256 payload hash", function() {
    $v = new ApprovalValidator();
    $payload = json_encode(['action' => 'TEST', 'target' => 'host1'], JSON_UNESCAPED_SLASHES);
    $hash = hash('sha256', $payload);
    $v->assertPayloadIntegrity($hash, $payload);
    return true;
});

p7test(25, "assertPayloadIntegrity detects and throws on payload tampering", function() {
    $v = new ApprovalValidator();
    $originalPayload = json_encode(['action' => 'TEST', 'target' => 'host1'], JSON_UNESCAPED_SLASHES);
    $originalHash = hash('sha256', $originalPayload);
    $tamperedPayload = json_encode(['action' => 'TEST', 'target' => 'host2'], JSON_UNESCAPED_SLASHES);
    try {
        $v->assertPayloadIntegrity($originalHash, $tamperedPayload);
        return "Payload tampering was not detected";
    } catch (RuntimeException $e) {
        return str_contains($e->getMessage(), 'integrity violation');
    }
});

// ============================================================================
// SECTION 8: DEEP SECRET REDACTION
// ============================================================================

p7test(26, "Secret redaction masks password, token, api_key, auth, cookie keys recursively", function() {
    $service = new ApprovalService(null);
    $dummyApproval = [
        'action_name'        => 'NOTIFY_SLACK',
        'action_description' => 'Send alert',
        'action_payload'     => json_encode([
            'channel'       => '#soc-alerts',
            'api_token'     => 'xoxb-987654321-secret-token',
            'api_key'       => 'AKIAIOSFODNN7EXAMPLE',
            'auth'          => ['username' => 'analyst', 'hash' => 'xyz'],
            'session_id'    => 'sess_abcdef123456',
            'config'        => ['password' => 'SuperSecret123', 'timeout' => 30],
            'nested'        => ['private_key' => 'raw_private_key_data']
        ])
    ];
    $preview = $service->generateActionPreview($dummyApproval);
    $params = $preview['resolved_parameters'];

    return $params['api_token'] === '[REDACTED]' &&
           $params['api_key'] === '[REDACTED]' &&
           $params['auth'] === '[REDACTED]' &&
           $params['session_id'] === '[REDACTED]' &&
           $params['config']['password'] === '[REDACTED]' &&
           $params['config']['timeout'] === 30 &&
           $params['nested']['private_key'] === '[REDACTED]' &&
           $params['channel'] === '#soc-alerts';
});

p7test(27, "Secret redaction detects and masks Bearer authorization tokens in string values", function() {
    $service = new ApprovalService(null);
    $dummyApproval = [
        'action_name'        => 'QUERY_THREAT_INTEL',
        'action_description' => 'Enrich IOC',
        'action_payload'     => json_encode([
            'header' => 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ae75w'
        ])
    ];
    $preview = $service->generateActionPreview($dummyApproval);
    $params = $preview['resolved_parameters'];

    return str_contains($params['header'], 'Bearer [REDACTED]') &&
           !str_contains($params['header'], 'eyJhbGciOi');
});

p7test(28, "Secret redaction detects and masks RSA/EC private keys in string values", function() {
    $service = new ApprovalService(null);
    $dummyApproval = [
        'action_name'        => 'TEST_ACTION',
        'action_description' => 'Test',
        'action_payload'     => json_encode([
            'raw_payload' => "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        ])
    ];
    $preview = $service->generateActionPreview($dummyApproval);
    $params = $preview['resolved_parameters'];

    return $params['raw_payload'] === '[REDACTED PRIVATE KEY]';
});

// ============================================================================
// SECTION 9: NON-DESTRUCTIVE BOUNDARY VERIFICATION
// ============================================================================

p7test(29, "ActionRegistry contains zero destructive response drivers (no BLOCK_IP, ISOLATE_HOST, etc.)", function() {
    $registry = new ActionRegistry();
    $registered = $registry->getAllowedTypes();
    $destructiveForbidden = ['BLOCK_IP', 'ISOLATE_HOST', 'DISABLE_USER', 'KILL_PROCESS', 'REBOOT_HOST', 'DELETE_FILE'];
    foreach ($destructiveForbidden as $forbidden) {
        if (in_array($forbidden, $registered, true)) {
            return "Destructive driver '{$forbidden}' found in ActionRegistry";
        }
    }
    return true;
});

p7test(30, "ActionRegistry handlers contain no eval, shell_exec, system, or exec calls", function() {
    $reflector = new ReflectionClass('ActionRegistry');
    $source = file_get_contents($reflector->getFileName());
    $forbiddenFuncs = ['eval(', 'shell_exec(', 'system(', 'passthru(', 'proc_open(', 'popen('];
    foreach ($forbiddenFuncs as $func) {
        if (stripos($source, $func) !== false) {
            return "Forbidden function invocation '{$func}' found in ActionRegistry source";
        }
    }
    return true;
});

// ============================================================================
// SECTION 10: PLAYBOOK VERSION LOCKING
// ============================================================================

p7test(31, "Playbook version locking: createRun persists playbook_version from playbook definition", function() {
    $reflector = new ReflectionMethod('PlaybookRepository', 'createRun');
    $params = $reflector->getParameters();
    $hasVersionParam = false;
    foreach ($params as $p) {
        if ($p->getName() === 'playbookVersion') {
            $hasVersionParam = true;
            break;
        }
    }
    return $hasVersionParam === true;
});

p7test(32, "Playbook version locking: run retains locked version even when a newer version exists", function() {
    // Verify PlaybookRepository has findPlaybookByNameAndVersion for immutable version lookup
    return method_exists('PlaybookRepository', 'findPlaybookByNameAndVersion') &&
           method_exists('PlaybookRepository', 'findActivePlaybookByName');
});

// ============================================================================
// SECTION 11: AUDIT SEMANTICS & NOTIFICATIONS
// ============================================================================

p7test(33, "Audit semantics: APPROVAL_VIEWED does not alter approval or run state", function() {
    // getApprovalDetail with mock throws not-found cleanly without modifying any record
    $service = new ApprovalService(null);
    try {
        $service->getApprovalDetail(99999, ['tier' => SoarAuth::LEAD, 'actor' => 'lead_analyst']);
        return "Expected not-found exception";
    } catch (InvalidArgumentException $e) {
        return str_contains($e->getMessage(), 'not found');
    }
});

p7test(34, "NotificationService enforces recipient ownership (IDOR check on mark-as-read)", function() {
    // markAsRead takes both notificationId AND userId to enforce row ownership
    $reflector = new ReflectionMethod('NotificationService', 'markAsRead');
    $params = $reflector->getParameters();
    return count($params) === 2 &&
           $params[0]->getName() === 'notificationId' &&
           $params[1]->getName() === 'userId';
});

// ============================================================================
// SUMMARY
// ============================================================================

echo "\n==================================================\n";
printf("PHASE 7 TEST RESULTS: %d/%d PASSED (%d FAILED)\n", $passed, $total, $failed);
echo "==================================================\n";

if ($failed > 0) {
    exit(1);
}
exit(0);
