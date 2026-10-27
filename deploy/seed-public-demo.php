<?php
if (PHP_SAPI !== 'cli' || getenv('APP_ENV') !== 'public-demo') { http_response_code(404); exit(1); }
require __DIR__.'/../includes/db.php';
require __DIR__.'/../includes/soar/SoarAuth.php';
require __DIR__.'/../includes/soar/DemoService.php';
$id=(int)$pdo->query("SELECT id FROM users WHERE username='admin'")->fetchColumn();
(new DemoService($pdo))->create($id, '00000000000000000000000000000001');
echo "Labeled training case is ready.\n";
