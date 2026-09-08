<?php
/**
 * ThreatPulse SOAR - Playbook Selector
 *
 * Deterministically recommends playbooks for an incident based on
 * risk score, priority, severity, category, and IOC assessment.
 *
 * DOES NOT automatically execute playbooks — returns recommendations only.
 * Selection is rule-based, reproducible, and auditable.
 */
class PlaybookSelector {

    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
    }

    /**
     * Return ranked recommendations with explanatory reasons.
     *
     * @param array $incident  Incident DB row
     * @param array $iocs      IOC rows with 'assessment' field
     * @param int   $alertCount Number of correlated alerts
     * @return array  [['playbook_name' => ..., 'reasons' => [...], 'score' => int], ...]
     */
    public function recommend(array $incident, array $iocs = [], int $alertCount = 1): array {
        $priority  = strtoupper($incident['priority']  ?? 'P4');
        $severity  = strtoupper($incident['severity']  ?? 'INFO');
        $category  = strtoupper($incident['attack_category'] ?? '');
        $riskScore = (int)($incident['risk_score']     ?? 0);

        $assessments = array_map(fn($i) => strtoupper($i['assessment'] ?? 'UNKNOWN'), $iocs);
        $hasMalicious   = in_array('MALICIOUS', $assessments, true);
        $hasSuspicious  = in_array('SUSPICIOUS', $assessments, true);

        $candidates = [];

        // Rule 1: P1 / P2 → High-Priority Investigation
        if (in_array($priority, ['P1', 'P2'], true)) {
            $candidates[] = [
                'playbook_name' => 'p1_investigation',
                'display_name'  => 'P1 Investigation',
                'reasons'       => ["Incident priority {$priority} requires immediate investigation."],
                'score'         => 100,
            ];
        }

        // Rule 2: RCE or SSTI category
        if (in_array($category, ['RCE', 'SSTI'], true)) {
            $candidates[] = [
                'playbook_name' => 'p1_investigation',
                'display_name'  => 'P1 Investigation',
                'reasons'       => ["{$category} attack category detected — high-priority investigation warranted."],
                'score'         => 90,
            ];
        }

        // Rule 3: Malicious IOC present
        if ($hasMalicious) {
            $candidates[] = [
                'playbook_name' => 'malicious_ioc_investigation',
                'display_name'  => 'Malicious IOC Investigation',
                'reasons'       => ['One or more MALICIOUS IOC assessments present — IOC enrichment and evidence required.'],
                'score'         => 85,
            ];
        }

        // Rule 4: High correlated alert volume
        if ($alertCount >= 4) {
            $candidates[] = [
                'playbook_name' => 'p1_investigation',
                'display_name'  => 'P1 Investigation',
                'reasons'       => ["{$alertCount} correlated alerts indicate broad attack surface."],
                'score'         => 70,
            ];
        }

        // Rule 5: Suspicious IOC (lower priority)
        if ($hasSuspicious && !$hasMalicious) {
            $candidates[] = [
                'playbook_name' => 'malicious_ioc_investigation',
                'display_name'  => 'Malicious IOC Investigation',
                'reasons'       => ['Suspicious IOC detected — enrichment recommended.'],
                'score'         => 60,
            ];
        }

        // Merge by playbook_name, accumulate reasons
        $merged = [];
        foreach ($candidates as $c) {
            $name = $c['playbook_name'];
            if (isset($merged[$name])) {
                $merged[$name]['reasons'] = array_merge($merged[$name]['reasons'], $c['reasons']);
                $merged[$name]['score']   = max($merged[$name]['score'], $c['score']);
            } else {
                $merged[$name] = $c;
            }
        }

        // Sort by score descending
        usort($merged, fn($a, $b) => $b['score'] <=> $a['score']);

        return array_values($merged);
    }
}
