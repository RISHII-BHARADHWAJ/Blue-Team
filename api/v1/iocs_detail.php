<?php
/**
 * ThreatPulse SOAR - IOC Detail & Provenance REST API Endpoint
 * 
 * Endpoint: GET /api/v1/iocs_detail.php
 * 
 * Query Params:
 * - ?id=123 OR ?type=IPV4&value=198.51.100.1
 * 
 * Returns:
 * - IOC record metadata
 * - Linked incidents & contextual roles
 * - Full multi-provider enrichment results & provenance
 * - Current normalized assessment (BENIGN, SUSPICIOUS, MALICIOUS, CONFLICTING, UNKNOWN)
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/IocRepository.php';
require_once __DIR__ . '/../../includes/soar/EnrichmentService.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'unauthorized', 'message' => 'Authentication required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    echo json_encode(['success' => false, 'error' => 'method_not_allowed'], JSON_UNESCAPED_SLASHES);
    exit;
}

$repo = new IocRepository($pdo);
$enrichmentService = new EnrichmentService($pdo);

$iocId = isset($_GET['id']) && is_numeric($_GET['id']) ? (int)$_GET['id'] : null;
$type = !empty($_GET['type']) ? strtoupper(trim($_GET['type'])) : null;
$value = !empty($_GET['value']) ? trim($_GET['value']) : null;

$ioc = null;
if ($iocId) {
    $ioc = $repo->find($iocId);
} elseif ($type && $value) {
    $ioc = $repo->findByTypeValue($type, $value);
}

if (!$ioc) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'not_found', 'message' => 'IOC record not found.'], JSON_UNESCAPED_SLASHES);
    exit;
}

try {
    // 1. Fetch linked incidents
    $stmt = $pdo->prepare("
        SELECT ii.incident_id, ii.role, ii.discovered_at, i.incident_number, i.title, i.status, i.severity
        FROM incident_iocs ii
        JOIN incidents i ON ii.incident_id = i.id
        WHERE ii.ioc_id = ?
        ORDER BY ii.discovered_at DESC
    ");
    $stmt->execute([$ioc['id']]);
    $linkedIncidents = $stmt->fetchAll();

    // 2. Fetch enrichment history
    $enrichments = $repo->getIocEnrichments((int)$ioc['id']);

    // 3. Current aggregate assessment
    $providerResults = [];
    foreach ($enrichments as $enr) {
        $parsed = is_array($enr['parsed_summary']) ? $enr['parsed_summary'] : [];
        $providerResults[$enr['provider']] = new ProviderResult(
            provider:       $enr['provider'],
            status:         $enr['status'],
            ioc_type:       $ioc['ioc_type'],
            ioc_value:      $ioc['ioc_value'],
            reputation:     (int)($parsed['reputation'] ?? 0),
            confidence:     (int)($parsed['confidence'] ?? 50),
            categories:     $parsed['categories'] ?? [],
            malware_family: $parsed['malware_family'] ?? null,
            first_seen:     $parsed['first_seen'] ?? null,
            last_seen:      $parsed['last_seen'] ?? null,
            raw_response:   $enr['raw_response'],
            summary:        $parsed['summary'] ?? $parsed,
            retrieved_at:   $enr['created_at'],
            cached:         true
        );
    }

    $assessment = $enrichmentService->aggregateAssessment($providerResults);

    echo json_encode([
        'success'    => true,
        'data'       => [
            'ioc'              => $ioc,
            'assessment'       => $assessment,
            'linked_incidents' => $linkedIncidents,
            'enrichments'      => $enrichments,
        ]
    ], JSON_UNESCAPED_SLASHES);
    exit;

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to retrieve IOC details.'], JSON_UNESCAPED_SLASHES);
    exit;
}
