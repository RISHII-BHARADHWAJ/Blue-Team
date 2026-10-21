<?php
/** Collect fixed public reputation feeds; inventory only, never observed attack events. */
declare(strict_types=1);
if (PHP_SAPI!=='cli') { http_response_code(405); exit('CLI ingestion only.'); }
require_once __DIR__ . '/includes/intel/run-collection.php';
exit(runFeedCollection(['emerging_threats','cins_army','blocklist_de'],array_slice($argv,1)));
