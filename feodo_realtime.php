<?php
/** Feodo inventory collection with durable history; no SIEM events are manufactured. */
declare(strict_types=1);
if (PHP_SAPI!=='cli') { http_response_code(405); exit('CLI ingestion only.'); }
require_once __DIR__ . '/includes/intel/run-collection.php';
exit(runFeedCollection(['feodo_tracker'],array_slice($argv,1)));
