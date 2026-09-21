<?php
/**
 * ThreatPulse SOAR - Risk Policy v1.0
 * 
 * Versioned repository of all deterministic risk scoring weights, thresholds,
 * factor caps, and priority mapping boundaries.
 * 
 * Centralizing weights here eliminates magic numbers and ensures auditability.
 */

class RiskPolicy {

    public const VERSION = 'v1.0';

    /**
     * Factor 1: Alert Severity Contributions
     */
    public const SEVERITY_WEIGHTS = [
        'CRITICAL' => 30,
        'HIGH'     => 22,
        'MEDIUM'   => 14,
        'LOW'      => 6,
        'INFO'     => 0,
    ];

    /**
     * Factor 2: Correlated Alert Volume Tiers & Cap
     */
    public const VOLUME_CAP = 18;
    public static function getVolumeContribution(int $alertCount): int {
        if ($alertCount <= 1) return 0;
        if ($alertCount <= 3) return 5;
        if ($alertCount <= 6) return 10;
        if ($alertCount <= 10) return 15;
        return self::VOLUME_CAP; // > 10 alerts = 18
    }

    /**
     * Factor 3: Attack-Chain Progression Tiers & Cap
     */
    public const ATTACK_CHAIN_CAP = 20;
    public const ATTACK_CHAIN_WEIGHTS = [
        'SINGLE_STAGE'              => 0,
        'TWO_STAGES'                => 8,
        'MULTI_STAGE'               => 15,
        'EXECUTION_RCE_PROGRESSION' => 18,
        'CREDENTIAL_ACCESS_TO_RCE'  => 20,
    ];

    /**
     * Factor 4: IOC Reputation Weights & Multi-IOC Bonus Cap
     */
    public const IOC_REPUTATION_WEIGHTS = [
        'MALICIOUS'   => 15,
        'SUSPICIOUS'  => 8,
        'CONFLICTING' => 4,
        'BENIGN'      => 0,
        'UNKNOWN'     => 0,
    ];
    public const MULTI_MALICIOUS_IOC_BONUS = 5;
    public const IOC_REPUTATION_CAP = 20;

    /**
     * Factor 5: IOC Provider Confidence Weights & Cap
     */
    public const IOC_CONFIDENCE_CAP = 5;
    public static function getIocConfidenceContribution(int $confidence, bool $isMalicious): int {
        if (!$isMalicious) return 0;
        if ($confidence >= 80) return 5;
        if ($confidence >= 50) return 3;
        if ($confidence > 0) return 1;
        return 0;
    }

    /**
     * Factor 6: Threat Intelligence Multi-Provider Agreement & Cap
     */
    public const TI_AGREEMENT_CAP = 8;
    public static function getTiAgreementContribution(int $independentProviderCount): int {
        if ($independentProviderCount <= 0) return 0;
        if ($independentProviderCount === 1) return 2;
        if ($independentProviderCount === 2) return 5;
        return self::TI_AGREEMENT_CAP; // >= 3 independent providers = 8
    }

    /**
     * Factor 7: Attack Category Weights
     */
    public const CATEGORY_WEIGHTS = [
        'RCE'   => 10,
        'SQLI'  => 8,
        'SSTI'  => 8,
        'LFI'   => 7,
        'SSH'   => 6,
        'XSS'   => 5,
        'OTHER' => 2,
    ];

    /**
     * Factor 8: Network Exposure / Context Weights
     */
    public const CONTEXT_WEIGHTS = [
        'EXTERNAL_TO_INTERNAL' => 5,
        'INTERNAL_TO_INTERNAL' => 2,
        'EXTERNAL_TO_EXTERNAL' => 0,
        'UNKNOWN'              => 0,
    ];

    /**
     * Factor 9: Attack Recency Tiers & Cap
     */
    public const RECENCY_CAP = 5;
    public static function getRecencyContribution(int $secondsSinceLastAlert): int {
        if ($secondsSinceLastAlert <= 300) return 5;   // <= 5 mins
        if ($secondsSinceLastAlert <= 1800) return 3;  // <= 30 mins
        if ($secondsSinceLastAlert <= 7200) return 1;  // <= 2 hours
        return 0;                                      // Older
    }

    /**
     * Factor 10: Asset Criticality Weights
     */
    public const ASSET_CRITICALITY_WEIGHTS = [
        'CRITICAL' => 10,
        'HIGH'     => 7,
        'MEDIUM'   => 4,
        'LOW'      => 1,
        'UNKNOWN'  => 0,
    ];

    /**
     * Score Limits
     */
    public const MIN_SCORE = 0;
    public const MAX_SCORE = 100;

    /**
     * Priority Mapping Boundaries
     */
    public static function mapScoreToPriority(int $score): string {
        if ($score >= 90) return 'P1';
        if ($score >= 75) return 'P2';
        if ($score >= 50) return 'P3';
        return 'P4';
    }
}
