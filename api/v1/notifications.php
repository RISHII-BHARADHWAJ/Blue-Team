<?php
/** Personal, named-session notifications. Recipient ownership applies to every tier. */
declare(strict_types=1);
require_once __DIR__.'/../../includes/db.php';
require_once __DIR__.'/../../includes/soar/SoarAuth.php';
require_once __DIR__.'/../../includes/soar/SoarCsrf.php';
require_once __DIR__.'/../../includes/soar/notifications/NotificationService.php';
$auth=SoarAuth::getContext($pdo);
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');
if($auth['actor']==='anonymous'){http_response_code(401);echo '{"success":false,"error":"unauthorized"}';exit;}
$service=new NotificationService($pdo);
try{
    $userId=$service->resolveUserId($auth);
    if($_SERVER['REQUEST_METHOD']==='GET'){
        if(isset($_GET['user_id']) && filter_var($_GET['user_id'],FILTER_VALIDATE_INT)!==$userId)throw new DomainException('Personal inboxes cannot be accessed on behalf of another user.');
        $unread=$_GET['unread_only']??'0';
        if(!in_array($unread,['0','1'],true))throw new InvalidArgumentException('unread_only must be 0 or 1.');
        $limit=filter_var($_GET['limit']??50,FILTER_VALIDATE_INT,['options'=>['min_range'=>1,'max_range'=>100]]);
        $page=filter_var($_GET['page']??1,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        if(!$limit||!$page)throw new InvalidArgumentException('Invalid page or limit.');
        $data=$service->inbox($auth,$unread==='1'?'unread':'all',$page,$limit);
        echo json_encode(['success'=>true,'user_id'=>$userId,'unread_count'=>$data['unread_count'],'count'=>count($data['notifications']),'data'=>$data['notifications'],'pagination'=>$data['pagination']],JSON_THROW_ON_ERROR);exit;
    }
    if($_SERVER['REQUEST_METHOD']==='POST'){
        SoarCsrf::enforce($auth);
        $raw=file_get_contents('php://input');
        if(str_contains(strtolower($_SERVER['CONTENT_TYPE']??''),'application/json')){
            try{$body=json_decode($raw,true,32,JSON_THROW_ON_ERROR);}catch(JsonException $e){throw new InvalidArgumentException('Invalid JSON body.');}
        }else $body=$_POST;
        if(!is_array($body))throw new InvalidArgumentException('An object body is required.');
        foreach(array_keys($body) as $field)if(!in_array($field,['notification_id','csrf_token'],true))throw new InvalidArgumentException('Only notification_id may be changed.');
        $id=filter_var($body['notification_id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
        if(!$id)throw new InvalidArgumentException('A valid notification_id is required.');
        $service->markReadBatch([$id],$auth);
        echo json_encode(['success'=>true,'notification_id'=>$id,'is_read'=>true,'unread_count'=>$service->getUnreadCount($userId)],JSON_THROW_ON_ERROR);exit;
    }
    header('Allow: GET, POST');http_response_code(405);echo '{"success":false,"error":"method_not_allowed"}';exit;
}catch(DomainException $e){http_response_code(403);$error=$e->getMessage();}
catch(OutOfBoundsException $e){http_response_code(404);$error=$e->getMessage();}
catch(InvalidArgumentException $e){http_response_code(422);$error=$e->getMessage();}
catch(Throwable $e){error_log('Personal notifications failed: '.$e->getMessage());http_response_code(500);$error='Notifications are temporarily unavailable.';}
echo json_encode(['success'=>false,'message'=>$error],JSON_THROW_ON_ERROR);
