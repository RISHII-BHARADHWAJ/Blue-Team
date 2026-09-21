<?php
/**
 * ThreatPulse SOAR - Incident Number Generator
 * 
 * Generates human-readable, deterministic, and race-condition-safe
 * incident identifiers in the format: INC-YYYY-NNNN (e.g., INC-2026-0001).
 * 
 * Safety: Uses database row locking (FOR UPDATE) within transaction contexts
 * to prevent duplicate sequence numbers during concurrent incident creations.
 */

class IncidentNumberGenerator {

    /**
     * Generate the next unique incident number for the current year.
     * 
     * @param ?PDO $pdo Database connection (optional for pure unit testing)
     * @param ?int $year Optional explicit year (defaults to current year)
     * @return string e.g. "INC-2026-0001"
     */
    public static function generate(?PDO $pdo = null, ?int $year = null): string {
        $year = $year ?: (int)date('Y');
        $prefix = "INC-{$year}-";

        if (!$pdo) {
            // Fallback for isolated unit tests without database connection
            static $mockCounter = 1;
            return sprintf("%s%04d", $prefix, $mockCounter++);
        }

        // Query the highest existing incident number for the target year with row locking
        $stmt = $pdo->prepare("
            SELECT incident_number 
            FROM incidents 
            WHERE incident_number LIKE ? 
            ORDER BY id DESC 
            LIMIT 1 
            FOR UPDATE
        ");
        $stmt->execute([$prefix . '%']);
        $lastNumber = $stmt->fetchColumn();

        $nextSeq = 1;
        if ($lastNumber && preg_match('/^INC-\d{4}-(\d+)$/', $lastNumber, $matches)) {
            $nextSeq = ((int)$matches[1]) + 1;
        }

        return sprintf("%s%04d", $prefix, $nextSeq);
    }
}
