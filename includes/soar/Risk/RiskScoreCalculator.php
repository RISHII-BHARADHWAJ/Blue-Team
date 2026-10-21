<?php
/**
 * ThreatPulse SOAR - Deterministic Risk Score Calculator
 * 
 * Executes pure mathematical calculation of risk factors based on Policy v1.1.
 * Produces point-by-point explainable factor breakdowns and overall scoring confidence.
 * 
 * Safety: ZERO machine learning, ZERO LLM calls, ZERO network queries.
 */

require_once __DIR__ . '/RiskPolicy.php';
require_once __DIR__ . '/RiskFactor.php';
require_once __DIR__ . '/RiskAssessment.php';

class RiskScoreCalculator {

    /**
     * Calculate complete risk assessment from provided incident telemetry.
     * 
     * @param array $incident Incident record
     * @param array $alerts Associated SIEM logs
     * @param array $iocs Associated IOC records & enrichment summaries
     * @param array $assetMetadata Optional asset inventory context
     * @param ?int $currentTimestamp Optional explicit timestamp for deterministic testing
     * @return RiskAssessment
     */
    public function calculate(
        array $incident,
        array $alerts = [],
        array $iocs = [],
        array $assetMetadata = [],
        ?int $currentTimestamp = null
    ): RiskAssessment {
        $factors = [];
        $now = $currentTimestamp ?? time();

        // ---------------------------------------------------------------------
        // 1. Alert Severity Factor (Max 30)
        // ---------------------------------------------------------------------
        $highestSeverity = strtoupper(trim($incident['severity'] ?? 'INFO'));
        foreach ($alerts as $a) {
            $sev = strtoupper(trim($a['severity'] ?? 'INFO'));
            if ($sev === 'WARNING') $sev = 'MEDIUM';
            $w = RiskPolicy::SEVERITY_WEIGHTS[$sev] ?? 0;
            $currW = RiskPolicy::SEVERITY_WEIGHTS[$highestSeverity] ?? 0;
            if ($w > $currW) {
                $highestSeverity = $sev;
            }
        }
        $sevContribution = RiskPolicy::SEVERITY_WEIGHTS[$highestSeverity] ?? 0;
        $factors[] = new RiskFactor(
            name:         'alert_severity',
            value:        $highestSeverity,
            contribution: $sevContribution,
            max_possible: 30,
            reason:       "Highest incident or attached alert classification is {$highestSeverity}."
        );

        // ---------------------------------------------------------------------
        // 2. Alert Volume Factor (Max 18)
        // ---------------------------------------------------------------------
        $alertCount = count($alerts);
        $volContribution = RiskPolicy::getVolumeContribution($alertCount);
        $factors[] = new RiskFactor(
            name:         'alert_volume',
            value:        "{$alertCount} alerts",
            contribution: $volContribution,
            max_possible: RiskPolicy::VOLUME_CAP,
            reason:       "Correlated volume of {$alertCount} alert(s) attached to case."
        );

        // ---------------------------------------------------------------------
        // 3. Attack-Chain Progression Factor (Max 20)
        // ---------------------------------------------------------------------
        // Unknown categories are not observed attack-chain stages.
        // In particular, a default incident category of OTHER must not turn
        // two concrete alert categories into a spurious three-stage chain.
        $categories = array_values(array_filter(array_unique(array_merge(
            [!empty($incident['attack_category']) ? strtoupper(trim($incident['attack_category'])) : 'OTHER'],
            array_map(fn($a) => strtoupper(trim($a['category'] ?? 'OTHER')), $alerts)
        )), fn($category) => $category !== '' && $category !== 'OTHER'));

        $chainType = 'SINGLE_STAGE';
        if (in_array('SSH', $categories, true) && in_array('RCE', $categories, true)) {
            $chainType = 'CREDENTIAL_ACCESS_TO_RCE';
        } elseif (count($categories) >= 2 && in_array('RCE', $categories, true)) {
            $chainType = 'EXECUTION_RCE_PROGRESSION';
        } elseif (count($categories) >= 3) {
            $chainType = 'MULTI_STAGE';
        } elseif (count($categories) === 2) {
            $chainType = 'TWO_STAGES';
        }

        $chainContribution = RiskPolicy::ATTACK_CHAIN_WEIGHTS[$chainType] ?? 0;
        $factors[] = new RiskFactor(
            name:         'attack_chain',
            value:        $chainType,
            contribution: $chainContribution,
            max_possible: RiskPolicy::ATTACK_CHAIN_CAP,
            reason:       "Category pattern {$chainType} across: " . implode(', ', $categories) . ". This heuristic does not verify an attack sequence."
        );

        // ---------------------------------------------------------------------
        // 4. IOC Reputation Factor (Max 20)
        // ---------------------------------------------------------------------
        $maliciousIocCount = 0;
        $strongestIocAssessment = 'UNKNOWN';
        $highestConfidenceScore = 0;
        $distinctProviders = [];

        foreach ($iocs as $ioc) {
            $assessment = strtoupper(trim($ioc['assessment'] ?? 'UNKNOWN'));
            if ($assessment === 'MALICIOUS') {
                $maliciousIocCount++;
                $strongestIocAssessment = 'MALICIOUS';
            } elseif ($assessment === 'SUSPICIOUS' && $strongestIocAssessment !== 'MALICIOUS') {
                $strongestIocAssessment = 'SUSPICIOUS';
            } elseif ($assessment === 'CONFLICTING' && !in_array($strongestIocAssessment, ['MALICIOUS', 'SUSPICIOUS'], true)) {
                $strongestIocAssessment = 'CONFLICTING';
            } elseif ($assessment === 'BENIGN' && $strongestIocAssessment === 'UNKNOWN') {
                $strongestIocAssessment = 'BENIGN';
            }

            $conf = max(0, min(100, (int)($ioc['confidence_score'] ?? 0)));
            if ($assessment === 'MALICIOUS') $highestConfidenceScore = max($highestConfidenceScore, $conf);

            if (!empty($ioc['providers']) && is_array($ioc['providers'])) {
                foreach ($ioc['providers'] as $pName => $pData) {
                    if (is_array($pData) && ($pData['status'] ?? '') === 'SUCCESS' && ($pData['reputation'] ?? 0) >= 50) {
                        $distinctProviders[$pName] = true;
                    }
                }
            }
        }

        $iocBaseRep = RiskPolicy::IOC_REPUTATION_WEIGHTS[$strongestIocAssessment] ?? 0;
        if ($maliciousIocCount >= 2) {
            $iocBaseRep = min(RiskPolicy::IOC_REPUTATION_CAP, $iocBaseRep + RiskPolicy::MULTI_MALICIOUS_IOC_BONUS);
        }
        $factors[] = new RiskFactor(
            name:         'ioc_reputation',
            value:        $strongestIocAssessment . ($maliciousIocCount >= 2 ? ' (Multi-IOC)' : ''),
            contribution: $iocBaseRep,
            max_possible: RiskPolicy::IOC_REPUTATION_CAP,
            reason:       "Strongest indicator assessment is {$strongestIocAssessment} ({$maliciousIocCount} malicious IOCs observed)."
        );

        // ---------------------------------------------------------------------
        // 5. IOC Confidence Factor (Max 5)
        // ---------------------------------------------------------------------
        $isMalicious = ($strongestIocAssessment === 'MALICIOUS');
        $iocConfContribution = RiskPolicy::getIocConfidenceContribution($highestConfidenceScore, $isMalicious);
        $factors[] = new RiskFactor(
            name:         'ioc_confidence',
            value:        "Confidence {$highestConfidenceScore}%",
            contribution: $iocConfContribution,
            max_possible: RiskPolicy::IOC_CONFIDENCE_CAP,
            reason:       "Threat intelligence provider classification confidence level of {$highestConfidenceScore}%."
        );

        // ---------------------------------------------------------------------
        // 6. Threat Intelligence Multi-Provider Agreement (Max 8)
        // ---------------------------------------------------------------------
        $providerAgreementCount = count($distinctProviders);
        $tiContribution = RiskPolicy::getTiAgreementContribution($providerAgreementCount);
        $factors[] = new RiskFactor(
            name:         'ti_agreement',
            value:        "{$providerAgreementCount} independent provider(s)",
            contribution: $tiContribution,
            max_possible: RiskPolicy::TI_AGREEMENT_CAP,
            reason:       "{$providerAgreementCount} distinct external intelligence feed(s) corroborate threat."
        );

        // ---------------------------------------------------------------------
        // 7. Incident Attack Category Factor (Max 10)
        // ---------------------------------------------------------------------
        $dominantCat = 'OTHER';
        $maxCatWeight = 0;
        foreach ($categories as $cat) {
            $w = RiskPolicy::CATEGORY_WEIGHTS[$cat] ?? 2;
            if ($w > $maxCatWeight) {
                $maxCatWeight = $w;
                $dominantCat = $cat;
            }
        }
        $factors[] = new RiskFactor(
            name:         'incident_category',
            value:        $dominantCat,
            contribution: $maxCatWeight,
            max_possible: 10,
            reason:       "Dominant attack category evaluated as {$dominantCat}."
        );

        // ---------------------------------------------------------------------
        // 8. Network Exposure / Context Factor (Max 5)
        // ---------------------------------------------------------------------
        $contextType = 'UNKNOWN';
        foreach ($alerts as $alert) {
            $source = self::addressScope($alert['source_ip'] ?? '');
            $destination = self::addressScope($alert['destination_ip'] ?? '');
            $candidate = match ([$source, $destination]) {
                ['PUBLIC', 'PRIVATE'] => 'EXTERNAL_TO_INTERNAL',
                ['PRIVATE', 'PRIVATE'] => 'INTERNAL_TO_INTERNAL',
                ['PUBLIC', 'PUBLIC'] => 'EXTERNAL_TO_EXTERNAL',
                default => 'UNKNOWN',
            };
            if ((RiskPolicy::CONTEXT_WEIGHTS[$candidate] ?? 0) > (RiskPolicy::CONTEXT_WEIGHTS[$contextType] ?? 0)) $contextType = $candidate;
            elseif ($contextType === 'UNKNOWN' && $candidate !== 'UNKNOWN') $contextType = $candidate;
        }
        $contextContribution = RiskPolicy::CONTEXT_WEIGHTS[$contextType] ?? 0;
        $factors[] = new RiskFactor(
            name:         'network_context',
            value:        $contextType,
            contribution: $contextContribution,
            max_possible: 5,
            reason:       "Reported source/destination topology: {$contextType}. Missing or special-use addresses add no exposure points."
        );

        // ---------------------------------------------------------------------
        // 9. Attack Recency / Activity Factor (Max 5)
        // ---------------------------------------------------------------------
        $latestAlertTimestamp = null;
        foreach ($alerts as $a) {
            $raw = $a['event_timestamp'] ?? $a['timestamp'] ?? null;
            // Stored canonical and legacy DATETIME values are interpreted as UTC.
            $ts = false;
            if (is_string($raw) && $raw !== '') {
                try { $ts = (new DateTimeImmutable($raw, new DateTimeZone('UTC')))->getTimestamp(); }
                catch (Exception $e) { /* Invalid source time contributes no recency. */ }
            }
            if ($ts !== false && $ts > 0 && $ts <= $now) {
                $latestAlertTimestamp = max($latestAlertTimestamp ?? 0, $ts);
            }
        }
        $secondsSinceLast = $latestAlertTimestamp === null ? null : $now - $latestAlertTimestamp;
        $recencyContribution = $secondsSinceLast === null ? 0 : RiskPolicy::getRecencyContribution($secondsSinceLast);
        $factors[] = new RiskFactor(
            name:         'attack_recency',
            value:        $secondsSinceLast === null ? 'UNKNOWN' : "{$secondsSinceLast}s ago",
            contribution: $recencyContribution,
            max_possible: RiskPolicy::RECENCY_CAP,
            reason:       $secondsSinceLast === null ? 'No valid, non-future alert timestamp; no recency points.'
                          : "Latest non-future alert timestamp was {$secondsSinceLast} seconds before assessment (UTC)."
        );

        // ---------------------------------------------------------------------
        // 10. Asset Criticality Factor (Max 10)
        // ---------------------------------------------------------------------
        $assetCrit = strtoupper(trim($assetMetadata['criticality'] ?? 'UNKNOWN'));
        $assetContribution = RiskPolicy::ASSET_CRITICALITY_WEIGHTS[$assetCrit] ?? 0;
        $factors[] = new RiskFactor(
            name:         'asset_criticality',
            value:        $assetCrit,
            contribution: $assetContribution,
            max_possible: 10,
            reason:       $assetCrit === 'UNKNOWN' 
                          ? 'Asset inventory not configured; neutral baseline applied.' 
                          : "Target asset flagged as {$assetCrit} criticality."
        );

        // ---------------------------------------------------------------------
        // Total Score Calculation & Priority Mapping
        // ---------------------------------------------------------------------
        $rawScore = 0;
        foreach ($factors as $f) {
            $rawScore += $f->contribution;
        }
        $finalScore = max(RiskPolicy::MIN_SCORE, min(RiskPolicy::MAX_SCORE, $rawScore));
        $priority = RiskPolicy::mapScoreToPriority($finalScore);

        // ---------------------------------------------------------------------
        // Scoring Confidence Determination
        // ---------------------------------------------------------------------
        $confidence = 'LOW';
        if ($providerAgreementCount >= 2 || $maliciousIocCount >= 2 || ($alertCount >= 3 && ($highestSeverity === 'CRITICAL' || $highestSeverity === 'HIGH'))) {
            $confidence = 'HIGH';
        } elseif ($providerAgreementCount >= 1 || $alertCount >= 2 || $strongestIocAssessment === 'SUSPICIOUS' || $highestSeverity === 'HIGH') {
            $confidence = 'MEDIUM';
        }

        return new RiskAssessment(
            score:          $finalScore,
            priority:       $priority,
            confidence:     $confidence,
            factors:        $factors,
            policy_version: RiskPolicy::VERSION,
            calculated_at:  gmdate('Y-m-d H:i:s', $now),
            calculated_by:  'RiskScoreCalculator'
        );
    }
    private static function addressScope(string $ip): string {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return 'UNKNOWN';
        $bytes = inet_pton($ip);
        if (strlen($bytes) === 4) {
            $a = ord($bytes[0]); $b = ord($bytes[1]); $c = ord($bytes[2]);
            if ($a === 10 || ($a === 172 && $b >= 16 && $b <= 31) || ($a === 192 && $b === 168)) return 'PRIVATE';
            // Documentation, shared address and benchmarking ranges are not public exposure evidence.
            if (($a === 192 && $b === 0 && $c === 2) || ($a === 198 && $b === 51 && $c === 100)
                || ($a === 203 && $b === 0 && $c === 113) || ($a === 100 && $b >= 64 && $b <= 127)
                || ($a === 198 && ($b === 18 || $b === 19)) || $a >= 224) return 'UNKNOWN';
        } else {
            if ((ord($bytes[0]) & 0xfe) === 0xfc) return 'PRIVATE';
            if (ord($bytes[0]) === 0xff || substr($bytes, 0, 4) === hex2bin('20010db8')) return 'UNKNOWN';
        }
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ? 'PUBLIC' : 'UNKNOWN';
    }

}
