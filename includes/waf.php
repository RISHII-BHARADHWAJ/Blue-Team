<?php
// Simple WAF / Logger for Blue Team Training
// Detects basic attack patterns and logs them to fulllogs.log

function waf_log_attack($type, $payload) {
    $logFile = __DIR__ . '/../fulllogs.log';
    $timestamp = date('M d H:i:s');
    $host = 'web-01'; // Simulated host
    $process = 'apache2';
    $ip = $_SERVER['REMOTE_ADDR'];
    $method = $_SERVER['REQUEST_METHOD'];
    $uri = $_SERVER['REQUEST_URI'];
    
    // Format: Date Host Process: Message rhost=IP
    // Example: Feb 08 16:45:12 web-01 apache2: [error] [client 192.168.1.50] ModSecurity: Access denied with code 403 (phase 2). Pattern match "UNION SELECT" at ARGS:id. [id "1005"] [msg "SQL Injection Attempt"] [data "UNION SELECT"] [severity "CRITICAL"] rhost=192.168.1.50
    
    $message = "[error] [client {$ip}] WAF Detection: Pattern match \"{$type}\" in request. [msg \"{$type} Attempt\"] [data \"{$payload}\"] [severity \"CRITICAL\"] [uri \"{$uri}\"]";
    
    $logLine = "$timestamp $host $process: $message rhost=$ip" . PHP_EOL;
    
    // Append to log file
    file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
}

function waf_scan_array($data, $context = '') {
    $patterns = [
        'SQLi' => '/(union select|union all select|select.*from|information_schema|or\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1|;\s*--)/i',
        'XSS' => '/(<script>|javascript:|onerror=|onload=|document\.cookie|alert\(|prompt\()/i',
        'RCE' => '/(cmd=|exec\(|system\(|shell_exec\(|passthru\(|`.*`|\|\|.*(?:ls|cat|whoami))/i',
        'LFI' => '/(\.\.\/|\.\.\\\|\/etc\/passwd|\/windows\/win.ini)/i',
        'SSTI' => '/(\{\{.*\}\}|\$\{.*\})/i' // Basic Twig/Jinja/EL
    ];

    foreach ($data as $key => $value) {
        if (is_array($value)) {
            waf_scan_array($value, $context . "[$key]");
            continue;
        }

        foreach ($patterns as $type => $regex) {
            if (preg_match($regex, urldecode($value))) {
                // Log the attack
                // Truncate payload to avoid huge logs
                $payload = substr(htmlspecialchars($value), 0, 50);
                waf_log_attack($type, $payload);
                return; // Log once per request to avoid flooding
            }
        }
    }
}

// Scan GET and POST
waf_scan_array($_GET);
waf_scan_array($_POST);
?>
