<?php
/**
 * ThreatPulse SOAR - IOC Search & Registry REST API Endpoint
 * 
 * Endpoint: GET /api/v1/iocs.php
 * 
 * Filters Supported:
 * - ioc_type (IPV4, IPV6, DOMAIN, URL, MD5, SHA256, EMAIL)
 * - ioc_value (substring search)
 * - reputation (minimum score)
 * - source_feed
 * - limit, offset
 * 
 * Security:
 * - Session or Bearer authentication
 * - Tier 1+ read access
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');

require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/IocRepository.php';

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

$filters = [
    'ioc_type'    => !empty($_GET['ioc_type']) ? strtoupper(trim($_GET['ioc_type'])) : null,
    'ioc_value'   => !empty($_GET['ioc_value']) ? trim($_GET['ioc_value']) : null,
    'reputation'  => isset($_GET['reputation']) && is_numeric($_GET['reputation']) ? (int)$_GET['reputation'] : null,
    'source_feed' => !empty($_GET['source_feed']) ? trim($_GET['source_feed']) : null,
];

$limit = isset($_GET['limit']) && is_numeric($_GET['limit']) ? (int)$_GET['limit'] : 50;
$offset = isset($_GET['offset']) && is_numeric($_GET['offset']) ? (int)$_GET['offset'] : 0;

try {
    $iocs = $repo->listIocs($filters, $limit, $offset);

    echo json_encode([
        'success' => true,
        'count'   => count($iocs),
        'limit'   => $limit,
        'offset'  => $offset,
        'data'    => $iocs
    ], JSON_UNESCAPED_SLASHES);
    exit;

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'server_error', 'message' => 'Failed to query IOC registry.'], JSON_UNESCAPED_SLASHES);
    exit;
}
