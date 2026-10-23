<?php
declare(strict_types=1);
require_once __DIR__.'/../../includes/db.php';
require_once __DIR__.'/../../includes/soar/approvals/ApprovalQueueService.php';
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { http_response_code(401); echo json_encode(['success'=>false,'message'=>'Authentication required.']); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { header('Allow: GET'); http_response_code(405); echo json_encode(['success'=>false,'message'=>'Queue browsing supports GET only.']); exit; }
try {
    $data = (new ApprovalQueueService($pdo))->search($auth,$_GET);
    echo json_encode(['success'=>true]+$data,JSON_INVALID_UTF8_SUBSTITUTE);
} catch (DomainException $e) { http_response_code(403); echo json_encode(['success'=>false,'message'=>$e->getMessage()]); }
catch (InvalidArgumentException $e) { http_response_code(422); echo json_encode(['success'=>false,'message'=>$e->getMessage()]); }
catch (Throwable $e) { error_log('Approval queue unavailable: '.$e->getMessage()); http_response_code(503); echo json_encode(['success'=>false,'message'=>'Approval queue is temporarily unavailable.']); }
