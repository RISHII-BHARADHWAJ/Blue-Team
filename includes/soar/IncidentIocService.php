<?php
/**
 * ThreatPulse SOAR - Incident IOC Discovery & Enrichment Service
 * 
 * Orchestrates IOC discovery from incident telemetry:
 * 1. Inspects attached SIEM alerts
 * 2. Extracts candidate indicators
 * 3. Contextualizes roles (ATTACKER, TARGET, C2_SERVER, PAYLOAD_URL, DROPPED_FILE, EXFILTRATION_HOST)
 * 4. Upserts and attaches IOCs to incident
 * 5. Executes multi-provider threat intelligence enrichment
 * 6. Generates an incident-level enrichment summary
 * 
 * Non-Goal: Does NOT calculate or alter incident risk_score (Phase 5).
 */

require_once __DIR__ . '/IocExtractor.php';
require_once __DIR__ . '/IocRepository.php';
require_once __DIR__ . '/IncidentRepository.php';
require_once __DIR__ . '/EnrichmentService.php';

class IncidentIocService {
    private ?PDO $pdo;
    private IocExtractor $extractor;
    private IocRepository $iocRepo;
    private IncidentRepository $incRepo;
    private EnrichmentService $enrichmentService;

    public function __construct(
        ?PDO $pdo = null,
        ?EnrichmentService $enrichmentService = null
    ) {
        $this->pdo = $pdo;
        $this->extractor = new IocExtractor();
        $this->iocRepo = new IocRepository($pdo);
        $this->incRepo = new IncidentRepository($pdo);
        $this->enrichmentService = $enrichmentService ?: new EnrichmentService($pdo);
    }

    /**
     * Discover, attach, and enrich all IOCs for a given incident.
     * 
     * @param int $incidentId Target incident ID
     * @param bool $enrichNow Whether to trigger TI enrichment immediately (default: true)
     * @param string $actor Submitting identity
     * @return array Summary of discovered IOCs and enrichment results
     */
    public function processIncidentIocs(int $incidentId, bool $enrichNow = true, string $actor = 'system'): array {
        $incident = $this->incRepo->find($incidentId);
        if (!$incident) {
            throw new InvalidArgumentException("Incident #{$incidentId} does not exist.");
        }

        // 1. Fetch attached SIEM alerts
        $attachedAlerts = $this->incRepo->getAttachedAlerts($incidentId);
        $discovered = [];

        // 2. Extract IOCs from alerts
        foreach ($attachedAlerts as $alertRow) {
            $alertIocs = $this->extractor->extractFromAlert($alertRow, false);

            foreach ($alertIocs as $iocItem) {
                $role = $this->determineRole($iocItem, $alertRow);
                $key = $iocItem['type'] . ':' . $iocItem['value'];

                if (!isset($discovered[$key])) {
                    $discovered[$key] = [
                        'type'   => $iocItem['type'],
                        'value'  => $iocItem['value'],
                        'role'   => $role,
                        'source' => $iocItem['source'],
                    ];
                }
            }
        }

        // 3. Upsert and attach to incident_iocs
        $attachedIocs = [];
        foreach ($discovered as $item) {
            $iocId = $this->iocRepo->upsertIoc([
                'ioc_type'    => $item['type'],
                'ioc_value'   => $item['value'],
                'source_feed' => 'incident_' . $incidentId,
            ]);

            $this->iocRepo->attachToIncident($incidentId, $iocId, $item['role']);

            $attachedIocs[] = [
                'ioc_id' => $iocId,
                'type'   => $item['type'],
                'value'  => $item['value'],
                'role'   => $item['role'],
            ];
        }

        // 4. Enrich Attached IOCs (if enabled)
        $enrichmentResults = [];
        $maliciousCount = 0;
        $suspiciousCount = 0;
        $conflictingCount = 0;
        $benignCount = 0;
        $unknownCount = 0;

        if ($enrichNow) {
            foreach ($attachedIocs as $att) {
                try {
                    $res = $this->enrichmentService->enrichIoc($att['ioc_id'], false, $actor);
                    $enrichmentResults[] = $res;

                    $assess = $res['assessment']['assessment'] ?? 'UNKNOWN';
                    match ($assess) {
                        'MALICIOUS'   => $maliciousCount++,
                        'SUSPICIOUS'  => $suspiciousCount++,
                        'CONFLICTING' => $conflictingCount++,
                        'BENIGN'      => $benignCount++,
                        default       => $unknownCount++,
                    };
                } catch (Exception $e) {
                    $unknownCount++;
                }
            }
        }

        return [
            'incident_id'        => $incidentId,
            'incident_number'    => $incident['incident_number'],
            'total_iocs'         => count($attachedIocs),
            'attached_iocs'      => $attachedIocs,
            'summary'            => [
                'malicious_iocs'   => $maliciousCount,
                'suspicious_iocs'  => $suspiciousCount,
                'conflicting_iocs' => $conflictingCount,
                'benign_iocs'      => $benignCount,
                'unknown_iocs'     => $unknownCount,
            ],
            'enrichment_results' => $enrichmentResults,
        ];
    }

    /**
     * Contextually determine the functional role of an IOC in an incident.
     */
    private function determineRole(array $iocItem, array $alertRow): string {
        $type = $iocItem['type'];
        $source = $iocItem['source'];
        $msg = strtolower($alertRow['message'] ?? '');
        $cat = strtoupper($alertRow['category'] ?? '');

        if ($type === IocNormalizer::TYPE_URL) {
            return 'PAYLOAD_URL';
        }

        if ($type === IocNormalizer::TYPE_MD5 || $type === IocNormalizer::TYPE_SHA256) {
            return 'DROPPED_FILE';
        }

        if ($source === 'destination_ip') {
            return 'TARGET';
        }

        if (str_contains($msg, 'c2') || str_contains($msg, 'command-and-control') || str_contains($msg, 'beacon') || $cat === 'RCE') {
            return 'C2_SERVER';
        }

        if (str_contains($msg, 'exfil') || str_contains($msg, 'leak') || str_contains($msg, 'upload')) {
            return 'EXFILTRATION_HOST';
        }

        return 'ATTACKER';
    }
}
