<?php
declare(strict_types=1);
require_once __DIR__.'/../../includes/db.php';
require_once __DIR__.'/../../includes/soar/IncidentSeverityService.php';
require_once __DIR__.'/../../includes/soar/SoarCsrf.php';
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
function severityResponse(int $status,array $body): never { http_response_code($status);echo json_encode($body,JSON_INVALID_UTF8_SUBSTITUTE);exit; }
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') severityResponse(401,['success'=>false,'message'=>'Authentication required.']);
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Allow: POST');severityResponse(405,['success'=>false,'message'=>'Use POST to change severity.']); }
if ($auth['auth_method'] !== 'session' || empty($auth['user_id'])) severityResponse(403,['success'=>false,'message'=>'A named lead or administrator session is required.']);
SoarCsrf::enforce($auth);
if (strtolower(trim(explode(';',$_SERVER['CONTENT_TYPE'] ?? '')[0])) !== 'application/json') severityResponse(415,['success'=>false,'message'=>'Send application/json.']);
$raw = file_get_contents('php://input',false,null,0,16385);
if ($raw === false || strlen($raw)>16384) severityResponse(413,['success'=>false,'message'=>'Request body is too large.']);
try { $body = json_decode($raw,true,32,JSON_THROW_ON_ERROR); } catch (JsonException $e) { severityResponse(400,['success'=>false,'message'=>'Invalid JSON.']); }
if (!is_array($body) || array_is_list($body)) severityResponse(400,['success'=>false,'message'=>'Expected a JSON object.']);
if (array_diff(array_keys($body),['incident_id','severity','expected_severity','expected_priority','reason'])) severityResponse(422,['success'=>false,'message'=>'Only severity, expected case values and reason may be supplied.']);
$id = $body['incident_id'] ?? null;
if ((!is_int($id) && !is_string($id)) || !filter_var($id,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])) severityResponse(422,['success'=>false,'message'=>'A positive incident_id is required.']);
foreach (['severity','expected_severity','expected_priority','reason'] as $field) if (!is_string($body[$field] ?? null)) severityResponse(422,['success'=>false,'message'=>'Severity, expected values and text reason are required.']);
try {
    $result = (new IncidentSeverityService($pdo))->change($auth,(int)$id,$body['severity'],$body['expected_severity'],$body['expected_priority'],$body['reason']);
    severityResponse(200,['success'=>true,'data'=>$result]);
} catch (DomainException $e) { severityResponse(403,['success'=>false,'message'=>$e->getMessage()]); }
catch (OutOfBoundsException $e) { severityResponse(404,['success'=>false,'message'=>$e->getMessage()]); }
catch (IncidentSeverityConflict $e) { severityResponse(409,['success'=>false,'message'=>$e->getMessage()]); }
catch (InvalidArgumentException $e) { severityResponse(422,['success'=>false,'message'=>$e->getMessage()]); }
catch (Throwable $e) { error_log('Severity update failed: '.$e->getMessage());severityResponse(503,['success'=>false,'message'=>'Could not save severity. Check the case before retrying.']); }
