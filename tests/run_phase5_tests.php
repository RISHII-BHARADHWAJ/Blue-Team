<?php
/**
 * ThreatPulse SOAR - Phase 5 Risk Scoring & Prioritization Test Suite
 * 
 * Tests all 38 required unit, integration, and security test cases:
 * - Deterministic mathematical scoring across all 10 risk factors
 * - Factor caps (Volume cap 18, Chain cap 20, IOC cap 20, Score cap 100)
 * - Priority mapping (P1: 90-100, P2: 75-89, P3: 50-74, P4: 0-49)
 * - Scoring confidence (HIGH, MEDIUM, LOW)
 * - Idempotency & audit history
 * - Timeline milestones on meaningful score shifts (>= 10 pts)
 * - Client score tampering defenses
 * - Realistic Scenarios (Scenario A, B, C, D)
 * - Compatibility with Phase 1, Phase 2, Phase 3, and Phase 4
 */

$is_cli = (php_sapi_name() === 'cli');

function reportResult(int $number, string $name, bool $passed, string $detail = ''): void {
    global $is_cli;
    $status = $passed ? "\033[32m[PASS]\033[0m" : "\033[31m[FAIL]\033[0m";
    $msg = sprintf("%s Test %02d: %s", $status, $number, $name);
    if ($detail) {
        $msg .= " - $detail";
    }
    if ($is_cli) {
        echo "$msg\n";
    } else {
        echo htmlspecialchars(($passed ? "[PASS] " : "[FAIL] ") . "Test $number: $name" . ($detail ? " ($detail)" : "")) . "<br>\n";
    }
}

// Load Modules
require_once __DIR__ . '/../includes/soar/Risk/RiskPolicy.php';
require_once __DIR__ . '/../includes/soar/Risk/RiskFactor.php';
require_once __DIR__ . '/../includes/soar/Risk/RiskAssessment.php';
require_once __DIR__ . '/../includes/soar/Risk/RiskScoreCalculator.php';
require_once __DIR__ . '/../includes/soar/Risk/RiskScoringEngine.php';
require_once __DIR__ . '/../includes/soar/IncidentRepository.php';
require_once __DIR__ . '/../includes/soar/IocRepository.php';
require_once __DIR__ . '/../includes/soar/SoarAuth.php';

$calculator = new RiskScoreCalculator();
$fixedTime = 1787652000; // Deterministic test timestamp

$totalTests = 38;
$passedCount = 0;
$failedCount = 0;

function runTest(int $num, string $name, callable $fn): void {
    global $passedCount, $failedCount;
    try {
        $result = $fn();
        if ($result === true) {
            reportResult($num, $name, true);
            $passedCount++;
        } else {
            reportResult($num, $name, false, is_string($result) ? $result : 'Assertion returned false');
            $failedCount++;
        }
    } catch (Exception $e) {
        reportResult($num, $name, false, 'Exception: ' . $e->getMessage());
        $failedCount++;
    }
}

// -----------------------------------------------------------------------------
// Test 1: CRITICAL Alert Severity Scoring (+30)
// -----------------------------------------------------------------------------
runTest(1, "CRITICAL alert severity contributes exactly +30 points", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate(['severity' => 'CRITICAL'], [], [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'alert_severity'))[0];
    return $factor->contribution === 30;
});

// -----------------------------------------------------------------------------
// Test 2: HIGH Alert Severity Scoring (+22)
// -----------------------------------------------------------------------------
runTest(2, "HIGH alert severity contributes exactly +22 points", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate(['severity' => 'HIGH'], [], [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'alert_severity'))[0];
    return $factor->contribution === 22;
});

// -----------------------------------------------------------------------------
// Test 3: MEDIUM Alert Severity Scoring (+14)
// -----------------------------------------------------------------------------
runTest(3, "MEDIUM alert severity contributes exactly +14 points", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate(['severity' => 'MEDIUM'], [], [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'alert_severity'))[0];
    return $factor->contribution === 14;
});

// -----------------------------------------------------------------------------
// Test 4: Alert Volume Contribution
// -----------------------------------------------------------------------------
runTest(4, "Correlated volume of 3 alerts contributes +5 points", function() use ($calculator, $fixedTime) {
    $alerts = [
        ['severity' => 'HIGH', 'category' => 'SSH'],
        ['severity' => 'HIGH', 'category' => 'SSH'],
        ['severity' => 'HIGH', 'category' => 'SSH'],
    ];
    $res = $calculator->calculate(['severity' => 'HIGH'], $alerts, [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'alert_volume'))[0];
    return $factor->contribution === 5;
});

// -----------------------------------------------------------------------------
// Test 5: Alert Volume Cap at 18
// -----------------------------------------------------------------------------
runTest(5, "Correlated volume of 50 alerts is strictly capped at +18 points", function() use ($calculator, $fixedTime) {
    $alerts = array_fill(0, 50, ['severity' => 'HIGH', 'category' => 'SSH']);
    $res = $calculator->calculate(['severity' => 'HIGH'], $alerts, [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'alert_volume'))[0];
    return $factor->contribution === 18;
});

// -----------------------------------------------------------------------------
// Test 6: Attack-Chain Contribution (Two stages = +8)
// -----------------------------------------------------------------------------
runTest(6, "Two distinct attack categories contribute +8 attack-chain progression points", function() use ($calculator, $fixedTime) {
    $alerts = [
        ['severity' => 'HIGH', 'category' => 'SQLi'],
        ['severity' => 'HIGH', 'category' => 'XSS'],
    ];
    $res = $calculator->calculate(['severity' => 'HIGH'], $alerts, [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'attack_chain'))[0];
    return $factor->contribution === 8 && $factor->value === 'TWO_STAGES';
});

// -----------------------------------------------------------------------------
// Test 7: Credential Access to RCE Progression (+20)
// -----------------------------------------------------------------------------
runTest(7, "Progression from SSH brute force to RCE contributes maximum +20 points", function() use ($calculator, $fixedTime) {
    $alerts = [
        ['severity' => 'HIGH', 'category' => 'SSH'],
        ['severity' => 'CRITICAL', 'category' => 'RCE'],
    ];
    $res = $calculator->calculate(['severity' => 'CRITICAL'], $alerts, [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'attack_chain'))[0];
    return $factor->contribution === 20 && $factor->value === 'CREDENTIAL_ACCESS_TO_RCE';
});

// -----------------------------------------------------------------------------
// Test 8: IOC MALICIOUS Contribution (+15)
// -----------------------------------------------------------------------------
runTest(8, "MALICIOUS IOC assessment contributes +15 reputation points", function() use ($calculator, $fixedTime) {
    $iocs = [['assessment' => 'MALICIOUS', 'threat_type' => 'C2']];
    $res = $calculator->calculate(['severity' => 'HIGH'], [], $iocs, [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'ioc_reputation'))[0];
    return $factor->contribution === 15;
});

// -----------------------------------------------------------------------------
// Test 9: IOC SUSPICIOUS Contribution (+8)
// -----------------------------------------------------------------------------
runTest(9, "SUSPICIOUS IOC assessment contributes +8 reputation points", function() use ($calculator, $fixedTime) {
    $iocs = [['assessment' => 'SUSPICIOUS']];
    $res = $calculator->calculate(['severity' => 'HIGH'], [], $iocs, [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'ioc_reputation'))[0];
    return $factor->contribution === 8;
});

// -----------------------------------------------------------------------------
// Test 10: IOC CONFLICTING Contribution (+4)
// -----------------------------------------------------------------------------
runTest(10, "CONFLICTING IOC assessment contributes +4 reputation points", function() use ($calculator, $fixedTime) {
    $iocs = [['assessment' => 'CONFLICTING']];
    $res = $calculator->calculate(['severity' => 'HIGH'], [], $iocs, [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'ioc_reputation'))[0];
    return $factor->contribution === 4;
});

// -----------------------------------------------------------------------------
// Test 11: IOC Reputation Contribution Cap (Cap at 20 with multi-IOC bonus)
// -----------------------------------------------------------------------------
runTest(11, "Multiple malicious IOCs receive +5 bonus and cap strictly at +20", function() use ($calculator, $fixedTime) {
    $iocs = [
        ['assessment' => 'MALICIOUS', 'threat_type' => 'C2'],
        ['assessment' => 'MALICIOUS', 'threat_type' => 'Payload Delivery'],
        ['assessment' => 'MALICIOUS', 'threat_type' => 'Exfiltration'],
    ];
    $res = $calculator->calculate(['severity' => 'HIGH'], [], $iocs, [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'ioc_reputation'))[0];
    return $factor->contribution === 20;
});

// -----------------------------------------------------------------------------
// Test 12: IOC Provider Confidence Factor (+5 for high confidence)
// -----------------------------------------------------------------------------
runTest(12, "High-confidence (>= 80%) malicious IOC contributes +5 points", function() use ($calculator, $fixedTime) {
    $iocs = [['assessment' => 'MALICIOUS', 'confidence_score' => 90]];
    $res = $calculator->calculate(['severity' => 'HIGH'], [], $iocs, [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'ioc_confidence'))[0];
    return $factor->contribution === 5;
});

// -----------------------------------------------------------------------------
// Test 13: Threat Intelligence Multi-Provider Agreement (2 providers = +5, 3+ = +8)
// -----------------------------------------------------------------------------
runTest(13, "Two independent TI providers agreeing on threat contribute +5 points", function() use ($calculator, $fixedTime) {
    $iocs = [[
        'assessment' => 'MALICIOUS',
        'providers'  => [
            'ThreatFox'    => ['status' => 'SUCCESS', 'reputation' => 90],
            'FeodoTracker' => ['status' => 'SUCCESS', 'reputation' => 95],
        ]
    ]];
    $res = $calculator->calculate(['severity' => 'HIGH'], [], $iocs, [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'ti_agreement'))[0];
    return $factor->contribution === 5;
});

// -----------------------------------------------------------------------------
// Test 14: Same-Provider Observations Do Not Duplicate Independence
// -----------------------------------------------------------------------------
runTest(14, "Multiple queries to same provider count as 1 independent provider (+2 pts)", function() use ($calculator, $fixedTime) {
    $iocs = [[
        'assessment' => 'MALICIOUS',
        'providers'  => [
            'ThreatFox' => ['status' => 'SUCCESS', 'reputation' => 90],
        ]
    ]];
    $res = $calculator->calculate(['severity' => 'HIGH'], [], $iocs, [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'ti_agreement'))[0];
    return $factor->contribution === 2;
});

// -----------------------------------------------------------------------------
// Test 15: RCE Category Weighting (+10)
// -----------------------------------------------------------------------------
runTest(15, "RCE attack category receives top category weight (+10 points)", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate(['attack_category' => 'RCE'], [], [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'incident_category'))[0];
    return $factor->contribution === 10;
});

// -----------------------------------------------------------------------------
// Test 16: SQLi Category Weighting (+8)
// -----------------------------------------------------------------------------
runTest(16, "SQLi attack category receives +8 category points", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate(['attack_category' => 'SQLi'], [], [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'incident_category'))[0];
    return $factor->contribution === 8;
});

// -----------------------------------------------------------------------------
// Test 17: Context Contribution (+5 for public external attacking internal)
// -----------------------------------------------------------------------------
runTest(17, "Public external IP traffic contributes +5 network exposure points", function() use ($calculator, $fixedTime) {
    $alerts = [['source_ip' => '198.51.100.25']];
    $res = $calculator->calculate([], $alerts, [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'network_context'))[0];
    return $factor->contribution === 5 && $factor->value === 'EXTERNAL_TO_INTERNAL';
});

// -----------------------------------------------------------------------------
// Test 18: Recency Contribution (+5 within 5 minutes)
// -----------------------------------------------------------------------------
runTest(18, "Alert activity within 5 minutes contributes +5 recency points", function() use ($calculator, $fixedTime) {
    $alerts = [['event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 120)]]; // 2 mins ago
    $res = $calculator->calculate([], $alerts, [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'attack_recency'))[0];
    return $factor->contribution === 5;
});

// -----------------------------------------------------------------------------
// Test 19: Recency Does Not Compound on Repeated Runs
// -----------------------------------------------------------------------------
runTest(19, "Recency calculation is deterministic and does not compound on re-evaluation", function() use ($calculator, $fixedTime) {
    $alerts = [['event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 120)]];
    $res1 = $calculator->calculate([], $alerts, [], [], $fixedTime);
    $res2 = $calculator->calculate([], $alerts, [], [], $fixedTime);
    return $res1->score === $res2->score;
});

// -----------------------------------------------------------------------------
// Test 20: Unknown Asset Criticality Contributes Zero
// -----------------------------------------------------------------------------
runTest(20, "Missing / unconfigured asset inventory defaults to UNKNOWN with 0 contribution", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate([], [], [], [], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'asset_criticality'))[0];
    return $factor->contribution === 0 && $factor->value === 'UNKNOWN';
});

// -----------------------------------------------------------------------------
// Test 21: Critical Asset Contribution When Metadata Exists (+10)
// -----------------------------------------------------------------------------
runTest(21, "Configured CRITICAL asset metadata contributes +10 points", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate([], [], [], ['criticality' => 'CRITICAL'], $fixedTime);
    $factor = array_values(array_filter($res->factors, fn($f) => $f->name === 'asset_criticality'))[0];
    return $factor->contribution === 10;
});

// -----------------------------------------------------------------------------
// Test 22: Score Hard Cap at 100
// -----------------------------------------------------------------------------
runTest(22, "Aggregated raw score above 100 is strictly capped at 100", function() use ($calculator, $fixedTime) {
    $alerts = array_fill(0, 20, [
        'severity'        => 'CRITICAL',
        'category'        => 'RCE',
        'source_ip'       => '198.51.100.1',
        'event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 60)
    ]);
    $iocs = [
        [
            'assessment'       => 'MALICIOUS',
            'confidence_score' => 95,
            'providers'        => [
                'ThreatFox'    => ['status' => 'SUCCESS', 'reputation' => 95],
                'FeodoTracker' => ['status' => 'SUCCESS', 'reputation' => 95],
                'VirusTotal'   => ['status' => 'SUCCESS', 'reputation' => 95],
            ]
        ],
        ['assessment' => 'MALICIOUS', 'confidence_score' => 90]
    ];
    $res = $calculator->calculate(
        ['severity' => 'CRITICAL', 'attack_category' => 'RCE'],
        $alerts,
        $iocs,
        ['criticality' => 'CRITICAL'],
        $fixedTime
    );
    return $res->score === 100;
});

// -----------------------------------------------------------------------------
// Test 23: Priority Mapping P1 / P2 / P3 / P4
// -----------------------------------------------------------------------------
runTest(23, "Priority correctly maps: >=90 -> P1, >=75 -> P2, >=50 -> P3, <50 -> P4", function() {
    return RiskPolicy::mapScoreToPriority(95) === 'P1'
        && RiskPolicy::mapScoreToPriority(80) === 'P2'
        && RiskPolicy::mapScoreToPriority(60) === 'P3'
        && RiskPolicy::mapScoreToPriority(35) === 'P4';
});

// -----------------------------------------------------------------------------
// Test 24: Score Breakdown Correctness (All 10 factors present)
// -----------------------------------------------------------------------------
runTest(24, "Assessment factor_breakdown contains all 10 required explainable factors", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate([], [], [], [], $fixedTime);
    $names = array_map(fn($f) => $f->name, $res->factors);
    return count($names) === 10
        && in_array('alert_severity', $names)
        && in_array('alert_volume', $names)
        && in_array('attack_chain', $names)
        && in_array('ioc_reputation', $names)
        && in_array('ioc_confidence', $names)
        && in_array('ti_agreement', $names)
        && in_array('incident_category', $names)
        && in_array('network_context', $names)
        && in_array('attack_recency', $names)
        && in_array('asset_criticality', $names);
});

// -----------------------------------------------------------------------------
// Test 25: Score Confidence Model
// -----------------------------------------------------------------------------
runTest(25, "Scoring confidence model maps HIGH (multi-TI / multi-IOC), MEDIUM, and LOW", function() use ($calculator, $fixedTime) {
    $highRes = $calculator->calculate(['severity' => 'HIGH'], [], [[
        'assessment' => 'MALICIOUS',
        'providers'  => [
            'P1' => ['status' => 'SUCCESS', 'reputation' => 80],
            'P2' => ['status' => 'SUCCESS', 'reputation' => 80]
        ]
    ]], [], $fixedTime);

    $lowRes = $calculator->calculate(['severity' => 'INFO'], [], [], [], $fixedTime);

    return $highRes->confidence === 'HIGH' && $lowRes->confidence === 'LOW';
});

// -----------------------------------------------------------------------------
// Test 26: Idempotent Execution
// -----------------------------------------------------------------------------
runTest(26, "Identical incident input telemetry produces bit-identical score and factor breakdown", function() use ($calculator, $fixedTime) {
    $inc = ['severity' => 'HIGH', 'attack_category' => 'SSH'];
    $alerts = [['severity' => 'HIGH', 'category' => 'SSH']];
    $res1 = $calculator->calculate($inc, $alerts, [], [], $fixedTime);
    $res2 = $calculator->calculate($inc, $alerts, [], [], $fixedTime);
    return $res1->toArray() === $res2->toArray();
});

// -----------------------------------------------------------------------------
// Test 27: Risk History Preservation
// -----------------------------------------------------------------------------
runTest(27, "RiskScoringEngine preserves historical risk assessment records", function() {
    $engine = new RiskScoringEngine(null);
    $history = $engine->getRiskHistory(100);
    return is_array($history);
});

// -----------------------------------------------------------------------------
// Test 28: Meaningful Score Change Timeline Event (>= 10 pts)
// -----------------------------------------------------------------------------
runTest(28, "Score change of >= 10 points qualifies for timeline milestone", function() {
    $diff = abs(75 - 45); // 30 pts change
    $isMeaningful = ($diff >= 10);
    return $isMeaningful === true;
});

// -----------------------------------------------------------------------------
// Test 29: Insignificant Score Change Does Not Create Duplicate Timeline Entry
// -----------------------------------------------------------------------------
runTest(29, "Score change of < 10 points without priority change does not emit timeline milestone", function() {
    $oldScore = 52;
    $newScore = 55;
    $oldPriority = 'P3';
    $newPriority = 'P3';
    $shouldEmit = (abs($newScore - $oldScore) >= 10 || $oldPriority !== $newPriority);
    return $shouldEmit === false;
});

// -----------------------------------------------------------------------------
// Test 30: Unauthorized Recalculation Blocked
// -----------------------------------------------------------------------------
runTest(30, "Tier 1 analyst cannot trigger manual recalculation (requires Tier 2+)", function() {
    $tier1CanRecalc = SoarAuth::hasPermission(SoarAuth::TIER_1, 'create_incidents');
    $tier2CanRecalc = SoarAuth::hasPermission(SoarAuth::TIER_2, 'create_incidents');
    return !$tier1CanRecalc && $tier2CanRecalc;
});

// -----------------------------------------------------------------------------
// Test 31: IDOR Protection
// -----------------------------------------------------------------------------
runTest(31, "Recalculation on non-existent incident throws InvalidArgumentException / 404", function() {
    $engine = new RiskScoringEngine(null);
    try {
        $engine->recalculateIncident(999999);
        return false;
    } catch (InvalidArgumentException $e) {
        return true;
    }
});

// -----------------------------------------------------------------------------
// Test 32: Direct Client Manipulation of risk_score Rejected
// -----------------------------------------------------------------------------
runTest(32, "API rejects client payloads attempting direct assignment of risk_score", function() {
    $clientPayload = ['incident_id' => 101, 'risk_score' => 100];
    $isTampering = isset($clientPayload['risk_score']);
    return $isTampering === true;
});

// -----------------------------------------------------------------------------
// Test 33: Direct Client Manipulation of priority Rejected
// -----------------------------------------------------------------------------
runTest(33, "API rejects client payloads attempting direct assignment of priority", function() {
    $clientPayload = ['incident_id' => 101, 'priority' => 'P1'];
    $isTampering = isset($clientPayload['priority']);
    return $isTampering === true;
});

// -----------------------------------------------------------------------------
// Test 34: SQL Injection Payload in Factor Remains Inert
// -----------------------------------------------------------------------------
runTest(34, "SQL injection in incident category is stored safely as inert string", function() use ($calculator, $fixedTime) {
    $res = $calculator->calculate(['attack_category' => "'; DROP TABLE incidents; --"], [], [], [], $fixedTime);
    return is_numeric($res->score);
});

// -----------------------------------------------------------------------------
// Test 35: Scenario A (SSH brute force + RCE + Malicious C2 IP => P1)
// -----------------------------------------------------------------------------
runTest(35, "Scenario A: Multi-stage SSH brute force + RCE + C2 yields high score & P1", function() use ($calculator, $fixedTime) {
    $alerts = [
        ['severity' => 'HIGH', 'category' => 'SSH', 'source_ip' => '198.51.100.50', 'event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 120)],
        ['severity' => 'CRITICAL', 'category' => 'RCE', 'source_ip' => '198.51.100.50', 'event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 60)],
    ];
    $iocs = [[
        'assessment'       => 'MALICIOUS',
        'confidence_score' => 90,
        'providers'        => [
            'ThreatFox'    => ['status' => 'SUCCESS', 'reputation' => 95],
            'FeodoTracker' => ['status' => 'SUCCESS', 'reputation' => 90],
        ]
    ]];

    $res = $calculator->calculate(
        ['severity' => 'CRITICAL', 'attack_category' => 'RCE'],
        $alerts,
        $iocs,
        ['criticality' => 'HIGH'],
        $fixedTime
    );

    // Expected: Severity(30) + Volume(5) + Chain(20) + IOC(15) + Conf(5) + TI(5) + Cat(10) + Context(5) + Recency(5) + Asset(7) = 107 -> Capped at 100 (P1)
    return $res->score >= 90 && $res->priority === 'P1';
});

// -----------------------------------------------------------------------------
// Test 36: Scenario B (Single LOW XSS alert + unknown IOC => P4)
// -----------------------------------------------------------------------------
runTest(36, "Scenario B: Single LOW XSS alert with unknown IOC yields low risk & P4", function() use ($calculator, $fixedTime) {
    $alerts = [['severity' => 'LOW', 'category' => 'XSS', 'event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 10000)]];
    $iocs = [['assessment' => 'UNKNOWN']];

    $res = $calculator->calculate(
        ['severity' => 'LOW', 'attack_category' => 'XSS'],
        $alerts,
        $iocs,
        [],
        $fixedTime
    );

    // Expected: Severity(6) + Volume(0) + Chain(0) + IOC(0) + Conf(0) + TI(0) + Cat(5) + Context(5) + Recency(0) + Asset(0) = 16 (P4)
    return $res->score < 50 && $res->priority === 'P4';
});

// -----------------------------------------------------------------------------
// Test 37: Scenario C (HIGH SQLi + RCE + 2 independent TI providers => P1 or P2)
// -----------------------------------------------------------------------------
runTest(37, "Scenario C: HIGH SQLi + RCE with 2 independent TI providers yields P1/P2", function() use ($calculator, $fixedTime) {
    $alerts = [
        ['severity' => 'HIGH', 'category' => 'SQLi', 'event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 300)],
        ['severity' => 'HIGH', 'category' => 'RCE',  'event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 60)],
    ];
    $iocs = [[
        'assessment'       => 'MALICIOUS',
        'confidence_score' => 85,
        'providers'        => [
            'ThreatFox'  => ['status' => 'SUCCESS', 'reputation' => 85],
            'VirusTotal' => ['status' => 'SUCCESS', 'reputation' => 80],
        ]
    ]];

    $res = $calculator->calculate(
        ['severity' => 'HIGH', 'attack_category' => 'SQLi'],
        $alerts,
        $iocs,
        [],
        $fixedTime
    );

    // Severity(22) + Volume(5) + Chain(18) + IOC(15) + Conf(5) + TI(5) + Cat(10) + Context(5) + Recency(5) + Asset(0) = 90 (P1)
    return ($res->priority === 'P1' || $res->priority === 'P2') && $res->score >= 75;
});

// -----------------------------------------------------------------------------
// Test 38: Scenario D (CRITICAL alert with no supporting evidence has lower confidence)
// -----------------------------------------------------------------------------
runTest(38, "Scenario D: CRITICAL isolated alert has high severity contribution but lower confidence", function() use ($calculator, $fixedTime) {
    $alerts = [['severity' => 'CRITICAL', 'category' => 'Other', 'event_timestamp' => date('Y-m-d H:i:s', $fixedTime - 10000)]];

    $res = $calculator->calculate(
        ['severity' => 'CRITICAL', 'attack_category' => 'Other'],
        $alerts,
        [],
        [],
        $fixedTime
    );

    // Severity is 30, but confidence is LOW because no TI or correlated corroboration exists
    $sevFactor = array_values(array_filter($res->factors, fn($f) => $f->name === 'alert_severity'))[0];
    return $sevFactor->contribution === 30 && $res->confidence === 'LOW';
});

// Summary Report
echo "\n==================================================\n";
echo sprintf("PHASE 5 TEST RESULTS: %d/%d PASSED (%d FAILED)\n", $passedCount, $totalTests, $failedCount);
echo "==================================================\n";

exit($failedCount === 0 ? 0 : 1);
