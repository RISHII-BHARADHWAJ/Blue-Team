<?php
/**
 * ThreatPulse SOAR - IOC Repository
 * 
 * Data access layer for `iocs`, `incident_iocs`, and `enrichment_results`.
 * Enforces uniqueness on (ioc_type, ioc_value) and (incident_id, ioc_id).
 */

require_once __DIR__ . '/IocNormalizer.php';

class IocRepository {
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
    }

    /**
     * Find an IOC by integer ID.
     */
    public function find(int $id): ?array {
        if (!$this->pdo) return null;

        $stmt = $this->pdo->prepare("SELECT * FROM iocs WHERE id = ?");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Find an IOC by its type and canonical value.
     */
    public function findByTypeValue(string $type, string $value): ?array {
        if (!$this->pdo) return null;

        $stmt = $this->pdo->prepare("SELECT * FROM iocs WHERE ioc_type = ? AND ioc_value = ?");
        $stmt->execute([strtoupper(trim($type)), trim($value)]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Upsert an IOC record into the database.
     * 
     * @param array $data ['ioc_type', 'ioc_value', 'threat_type', 'malware_family', 'reputation_score', 'confidence_score', 'source_feed']
     * @return int IOC ID
     */
    public function upsertIoc(array $data): int {
        if (!$this->pdo) {
            static $mockIocId = 200;
            return $mockIocId++;
        }

        $type = strtoupper(trim($data['ioc_type']));
        $value = trim($data['ioc_value']);
        $threatType = !empty($data['threat_type']) ? trim($data['threat_type']) : null;
        $malwareFamily = !empty($data['malware_family']) ? trim($data['malware_family']) : null;
        $reputation = isset($data['reputation_score']) ? (int)$data['reputation_score'] : 0;
        $confidence = isset($data['confidence_score']) ? (int)$data['confidence_score'] : 50;
        $sourceFeed = !empty($data['source_feed']) ? trim($data['source_feed']) : 'manual';

        $stmt = $this->pdo->prepare("
            INSERT INTO iocs (
                ioc_type, ioc_value, threat_type, malware_family, 
                reputation_score, confidence_score, source_feed, 
                first_seen, last_seen, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), NOW())
            ON DUPLICATE KEY UPDATE
                threat_type = COALESCE(VALUES(threat_type), threat_type),
                malware_family = COALESCE(VALUES(malware_family), malware_family),
                reputation_score = GREATEST(reputation_score, VALUES(reputation_score)),
                confidence_score = VALUES(confidence_score),
                last_seen = NOW()
        ");

        $stmt->execute([
            $type, $value, $threatType, $malwareFamily, $reputation, $confidence, $sourceFeed
        ]);

        $existing = $this->findByTypeValue($type, $value);
        return $existing ? (int)$existing['id'] : (int)$this->pdo->lastInsertId();
    }

    /**
     * Associate an IOC with an incident in the incident_iocs junction.
     */
    public function attachToIncident(int $incidentId, int $iocId, string $role = 'ATTACKER'): bool {
        if (!$this->pdo) return true;

        $allowedRoles = ['ATTACKER', 'TARGET', 'C2_SERVER', 'PAYLOAD_URL', 'DROPPED_FILE', 'EXFILTRATION_HOST'];
        $roleUpper = in_array(strtoupper(trim($role)), $allowedRoles, true) ? strtoupper(trim($role)) : 'ATTACKER';

        $stmt = $this->pdo->prepare("
            INSERT INTO incident_iocs (incident_id, ioc_id, role, discovered_at)
            VALUES (?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE role = VALUES(role)
        ");
        return $stmt->execute([$incidentId, $iocId, $roleUpper]);
    }

    /**
     * Retrieve all IOCs attached to an incident.
     */
    public function getIncidentIocs(int $incidentId): array {
        if (!$this->pdo) return [];

        $stmt = $this->pdo->prepare("
            SELECT ii.id AS link_id, ii.role, ii.discovered_at,
                   i.id AS ioc_id, i.ioc_type, i.ioc_value, i.threat_type, i.malware_family,
                   i.reputation_score, i.confidence_score, i.source_feed, i.first_seen, i.last_seen
            FROM incident_iocs ii
            JOIN iocs i ON ii.ioc_id = i.id
            WHERE ii.incident_id = ?
            ORDER BY ii.discovered_at DESC
        ");
        $stmt->execute([$incidentId]);
        return $stmt->fetchAll();
    }

    /**
     * List IOCs with filtering.
     */
    public function listIocs(array $filters = [], int $limit = 50, int $offset = 0): array {
        if (!$this->pdo) return [];

        $limit = max(1, min(200, $limit));
        $offset = max(0, $offset);

        $where = ['1=1'];
        $params = [];

        if (!empty($filters['ioc_type'])) {
            $where[] = 'ioc_type = ?';
            $params[] = strtoupper(trim($filters['ioc_type']));
        }
        if (!empty($filters['ioc_value'])) {
            $where[] = 'ioc_value LIKE ?';
            $params[] = '%' . trim($filters['ioc_value']) . '%';
        }
        if (!empty($filters['reputation'])) {
            $where[] = 'reputation_score >= ?';
            $params[] = (int)$filters['reputation'];
        }
        if (!empty($filters['source_feed'])) {
            $where[] = 'source_feed = ?';
            $params[] = trim($filters['source_feed']);
        }

        $whereSql = implode(' AND ', $where);
        $sql = "SELECT * FROM iocs WHERE $whereSql ORDER BY last_seen DESC LIMIT ? OFFSET ?";

        $stmt = $this->pdo->prepare($sql);
        $idx = 1;
        foreach ($params as $p) {
            $stmt->bindValue($idx++, $p);
        }
        $stmt->bindValue($idx++, $limit, PDO::PARAM_INT);
        $stmt->bindValue($idx++, $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Save an enrichment result from an external threat intelligence provider.
     */
    public function saveEnrichmentResult(
        int $iocId,
        string $provider,
        string $status,
        ?array $rawResponse,
        ?array $parsedSummary,
        string $cachedUntil
    ): int {
        if (!$this->pdo) {
            static $mockEnrichId = 1;
            return $mockEnrichId++;
        }

        $rawJson = $rawResponse !== null ? json_encode($rawResponse, JSON_UNESCAPED_SLASHES) : null;
        $summaryJson = $parsedSummary !== null ? json_encode($parsedSummary, JSON_UNESCAPED_SLASHES) : null;

        $stmt = $this->pdo->prepare("
            INSERT INTO enrichment_results (
                ioc_id, provider, status, raw_response, parsed_summary, cached_until, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $iocId,
            substr($provider, 0, 50),
            $status,
            $rawJson,
            $summaryJson,
            $cachedUntil
        ]);

        return (int)$this->pdo->lastInsertId();
    }

    /**
     * Retrieve active, non-expired cached enrichment result for an IOC and provider.
     */
    public function getCachedEnrichment(int $iocId, string $provider): ?array {
        if (!$this->pdo) return null;

        $stmt = $this->pdo->prepare("
            SELECT * FROM enrichment_results 
            WHERE ioc_id = ? AND provider = ? AND cached_until > NOW()
            ORDER BY created_at DESC 
            LIMIT 1
        ");
        $stmt->execute([$iocId, $provider]);
        $row = $stmt->fetch();
        if (!$row) return null;

        if (!empty($row['raw_response']) && is_string($row['raw_response'])) {
            $row['raw_response'] = json_decode($row['raw_response'], true) ?: $row['raw_response'];
        }
        if (!empty($row['parsed_summary']) && is_string($row['parsed_summary'])) {
            $row['parsed_summary'] = json_decode($row['parsed_summary'], true) ?: $row['parsed_summary'];
        }

        return $row;
    }

    /**
     * Retrieve all historical enrichment results for an IOC.
     */
    public function getIocEnrichments(int $iocId): array {
        if (!$this->pdo) return [];

        $stmt = $this->pdo->prepare("
            SELECT * FROM enrichment_results 
            WHERE ioc_id = ? 
            ORDER BY created_at DESC
        ");
        $stmt->execute([$iocId]);
        $rows = $stmt->fetchAll();

        foreach ($rows as &$row) {
            if (!empty($row['raw_response']) && is_string($row['raw_response'])) {
                $row['raw_response'] = json_decode($row['raw_response'], true) ?: $row['raw_response'];
            }
            if (!empty($row['parsed_summary']) && is_string($row['parsed_summary'])) {
                $row['parsed_summary'] = json_decode($row['parsed_summary'], true) ?: $row['parsed_summary'];
            }
        }

        return $rows;
    }
}
