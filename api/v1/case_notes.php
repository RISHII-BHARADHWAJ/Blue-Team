<?php
/** Session-authored, append-only analyst notes. No author impersonation through body fields. */
declare(strict_types=1);
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/soar/SoarAuth.php';
require_once __DIR__ . '/../../includes/soar/SoarCsrf.php';
require_once __DIR__ . '/../../includes/soar/CaseNoteService.php';
function noteResponse(int $status, array $body): never {
    http_response_code($status); echo json_encode($body, JSON_UNESCAPED_SLASHES); exit;
}
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') noteResponse(401, ['success'=>false, 'error'=>'Authentication required.']);
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST'); noteResponse(405, ['success'=>false, 'error'=>'Only POST is supported.']);
}
if (!SoarAuth::hasPermission($auth['tier'], 'add_notes') || $auth['auth_method'] !== 'session' || empty($auth['user_id'])) {
    noteResponse(403, ['success'=>false, 'error'=>'Sign in with a named user account to author case notes.']);
}
SoarCsrf::enforce($auth);
$contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
if ($contentType !== 'application/json') noteResponse(415, ['success'=>false, 'error'=>'Send application/json.']);
$raw = file_get_contents('php://input', false, null, 0, 65537);
if ($raw === false || strlen($raw) > 65536) noteResponse(413, ['success'=>false, 'error'=>'Request body is too large.']);
try { $body = json_decode($raw, true, 512, JSON_THROW_ON_ERROR); }
catch (JsonException $e) { noteResponse(400, ['success'=>false, 'error'=>'Invalid JSON body.']); }
if (!is_array($body)) noteResponse(400, ['success'=>false, 'error'=>'Expected a JSON object.']);
$id = filter_var($body['incident_id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
if (!$id || !is_string($body['note'] ?? null)) noteResponse(422, ['success'=>false, 'error'=>'Positive incident_id and text note are required.']);
try {
    $note = (new CaseNoteService($pdo))->add($id, (int)$auth['user_id'], $body['note']);
    noteResponse(201, ['success'=>true, 'data'=>$note]);
} catch (LengthException $e) { noteResponse(422, ['success'=>false, 'error'=>$e->getMessage()]); }
catch (OutOfBoundsException $e) { noteResponse(404, ['success'=>false, 'error'=>$e->getMessage()]); }
catch (DomainException $e) { noteResponse(403, ['success'=>false, 'error'=>$e->getMessage()]); }
catch (Throwable $e) { error_log('Case note save failed: ' . $e->getMessage()); noteResponse(500, ['success'=>false, 'error'=>'Could not save the note. Your text has been retained; check the case before retrying.']); }
