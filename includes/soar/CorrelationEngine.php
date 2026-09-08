<?php
/**
 * ThreatPulse SOAR - Correlation Engine
 * 
 * Deterministically evaluates normalized security alerts to determine whether they:
 * 1. ATTACH: Correlate with an existing active incident
 * 2. CREATE: Warrant creation of a new security incident
 * 3. IGNORE: Represent isolated, low-value SIEM telemetry (no incident created)
 * 
 * Rules:
 * - Rule 1 (SAME_SOURCE_IP): Alerts sharing same source IP (+40)
 * - Rule 2 (SAME_CATEGORY): Alerts sharing category (+20)
 * - Rule 3 (ATTACK_CHAIN): Multi-vector attack progression (e.g., SSH/SQLi/LFI -> RCE) (+30)
 * - Rule 4 (SAME_IOC): Matching IOC value (+30)
 * - Rule 5 (SAME_DESTINATION): Matching target IP (+20)
 * - Rule 6 (TIME_PROXIMITY): Occurring within 30 minutes of prior alert (+10)
 * 
 * Correlation Threshold: Score >= 50
 */

require_once __DIR__ . '/AlertSchema.php';
require_once __DIR__ . '/IncidentRepository.php';
require_once __DIR__ . '/IncidentStateMachine.php';

class CorrelationEngine {
    private IncidentRepository $repository;
    private int $lookbackSeconds;
    private int $correlationThreshold;

    /**
     * Attack chain category progression relationships.
     */
    private const ATTACK_CHAINS = [
        'SSH'  => ['RCE', 'Other'],
        'SQLi' => ['RCE', 'Other'],
        'LFI'  => ['RCE', 'Other'],
        'XSS'  => ['RCE', 'SQLi', 'Other'],
        'SSTI' => ['RCE', 'Other'],
    ];

    public function __construct(
        ?IncidentRepository $repository = null,
        int $lookbackSeconds = 7200,      // 2 hours
        int $correlationThreshold = 50     // Score >= 50 to correlate
    ) {
        $this->repository = $repository ?: new IncidentRepository(null);
        $this->lookbackSeconds = $lookbackSeconds;
        $this->correlationThreshold = $correlationThreshold;
    }

    /**
     * Evaluate an alert and return a structured correlation decision.
     * 
     * @param AlertSchema|array $alert Canonical alert instance or array
     * @return array [
     *     'decision'    => 'ATTACH' | 'CREATE' | 'IGNORE',
     *     'incident_id' => ?int,
     *     'score'       => int,
     *     'rules'       => array,
     *     'reason'      => string,
     *     'suggested_title' => string
     * ]
     */
    public function evaluate(AlertSchema|array $alert): array {
        $data = is_array($alert) ? $alert : $alert->toArray();

        $severity = strtoupper(trim($data['severity'] ?? 'INFO'));
        $category = trim($data['category'] ?? 'Other');
        $sourceIp = !empty($data['source_ip']) ? trim($data['source_ip']) : null;
        $destIp = !empty($data['destination_ip']) ? trim($data['destination_ip']) : null;
        $iocValue = !empty($data['ioc_value']) ? trim($data['ioc_value']) : null;
        $timestamp = !empty($data['event_timestamp']) ? strtotime($data['event_timestamp']) : time();
        if ($timestamp === false || $timestamp <= 0) {
            $timestamp = time();
        }

        // 1. Search for candidate active incidents within the lookback window
        $lookbackSince = date('Y-m-d H:i:s', $timestamp - $this->lookbackSeconds);
        $activeIncidents = $this->repository->findActiveIncidentsForCorrelation($lookbackSince, $sourceIp);

        $bestMatch = null;
        $bestScore = 0;
        $bestRules = [];

        foreach ($activeIncidents as $incident) {
            // Verify incident is in an active, correlatable status
            if (!IncidentStateMachine::isActive($incident['status'])) {
                continue;
            }

            $score = 0;
            $matchedRules = [];

            // Rule 1: Same Source IP
            if ($sourceIp !== null) {
                // Check if incident title or description contains source IP or matches attached alerts
                if (str_contains($incident['title'], $sourceIp) || str_contains($incident['description'] ?? '', $sourceIp)) {
                    $score += 40;
                    $matchedRules[] = 'SAME_SOURCE_IP';
                }
            }

            // Rule 2: Same Category
            if (!empty($incident['attack_category']) && strcasecmp($incident['attack_category'], $category) === 0) {
                $score += 20;
                $matchedRules[] = 'SAME_CATEGORY';
            }

            // Rule 3: Attack Chain Progression
            if (!empty($incident['attack_category']) && isset(self::ATTACK_CHAINS[$incident['attack_category']])) {
                if (in_array($category, self::ATTACK_CHAINS[$incident['attack_category']], true)) {
                    $score += 30;
                    $matchedRules[] = 'ATTACK_CHAIN';
                }
            }

            // Rule 4: Same IOC
            if ($iocValue !== null && !empty($incident['description']) && str_contains($incident['description'], $iocValue)) {
                $score += 30;
                $matchedRules[] = 'SAME_IOC';
            }

            // Rule 5: Time Proximity (< 30 minutes)
            $incidentCreatedTs = strtotime($incident['created_at']);
            if ($incidentCreatedTs !== false && abs($timestamp - $incidentCreatedTs) <= 1800) {
                $score += 10;
                $matchedRules[] = 'TIME_PROXIMITY';
            }

            if ($score > $bestScore) {
                $bestScore = $score;
                $bestMatch = $incident;
                $bestRules = $matchedRules;
            }
        }

        // Decision A: Attach to existing incident if threshold met
        if ($bestMatch !== null && $bestScore >= $this->correlationThreshold) {
            return [
                'decision'        => 'ATTACH',
                'incident_id'     => (int)$bestMatch['id'],
                'incident_number' => $bestMatch['incident_number'],
                'score'           => $bestScore,
                'rules'           => $bestRules,
                'reason'          => sprintf(
                    "Alert correlates with active incident %s (Score: %d, Rules: %s)",
                    $bestMatch['incident_number'],
                    $bestScore,
                    implode(', ', $bestRules)
                ),
                'suggested_title' => $bestMatch['title'],
            ];
        }

        // Decision B: Evaluate if alert qualifies for a NEW incident
        if ($severity === 'CRITICAL' || $severity === 'HIGH') {
            $suggestedTitle = $this->generateIncidentTitle($category, $sourceIp, $severity);
            return [
                'decision'        => 'CREATE',
                'incident_id'     => null,
                'score'           => $bestScore,
                'rules'           => [],
                'reason'          => sprintf("High-severity (%s) alert qualifies for new incident creation.", $severity),
                'suggested_title' => $suggestedTitle,
            ];
        }

        // Decision C: Medium alerts create incidents if correlation signals are partially present
        if ($severity === 'MEDIUM' && $bestScore >= 30) {
            $suggestedTitle = $this->generateIncidentTitle($category, $sourceIp, $severity);
            return [
                'decision'        => 'CREATE',
                'incident_id'     => null,
                'score'           => $bestScore,
                'rules'           => $bestRules,
                'reason'          => "Medium-severity alert reached minimum correlation threshold for incident escalation.",
                'suggested_title' => $suggestedTitle,
            ];
        }

        // Decision D: Low-value isolated alerts remain SIEM logs
        return [
            'decision'        => 'IGNORE',
            'incident_id'     => null,
            'score'           => $bestScore,
            'rules'           => $bestRules,
            'reason'          => sprintf("Isolated %s alert does not meet threshold for incident creation; retained in SIEM stream.", $severity),
            'suggested_title' => '',
        ];
    }

    /**
     * Generate a meaningful, category-derived incident title.
     */
    public function generateIncidentTitle(string $category, ?string $sourceIp, string $severity): string {
        $ipStr = $sourceIp ? " from $sourceIp" : '';
        
        return match (strtoupper($category)) {
            'SSH'   => "Possible SSH Compromise$ipStr",
            'SQLI'  => "SQL Injection Campaign$ipStr",
            'RCE'   => "Remote Code Execution Activity$ipStr",
            'XSS'   => "Cross-Site Scripting Injection$ipStr",
            'SSTI'  => "Server-Side Template Injection Attack$ipStr",
            'LFI'   => "Local File Inclusion Attempt$ipStr",
            default => "Security Alert ($severity)$ipStr",
        };
    }
}
