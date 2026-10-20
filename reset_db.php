<?php
// Database reset is intentionally disabled: this endpoint must never be exposed
// through the web server or run automatically in a deployed environment.
http_response_code(404);
header('Content-Type: text/plain; charset=UTF-8');
exit('Not Found');
