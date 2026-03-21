<?php
$files = [
    'Linux' => 'temp_linux.log',
    'OpenSSH' => 'temp_openssh.log',
    'Apache' => 'temp_apache.log'
];

$normalized_logs = [];
$current_year = date('Y');

foreach ($files as $type => $file) {
    if (!file_exists($file)) continue;
    
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $entry = '';
        
        if ($type == 'Linux' || $type == 'OpenSSH') {
            // Format: M d H:i:s Host Process: Message
            // Example: Jun 14 15:16:01 combo sshd...
            // Just need to ensure it parses correctly.
            // Dashboard regex: ^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+)\s(\S+)\s([^:]+):\s(.*)$
            
            // LogHub Linux/SSH logs already match "M d H:i:s Host Process: Message" perfectly.
            // But let's randomize the month/day to be recent so the chart timeline looks active.
            
            // Extract parts
            if (preg_match('/^([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+)\s(\S+)\s([^:]+):\s(.*)$/', $line, $matches)) {
                 $date_part = $matches[1];
                 $host = $matches[2];
                 // Shorten host if it's an IP
                 if (strlen($host) > 15) $host = substr($host, 0, 15);
                 
                 $process = $matches[3];
                 $message = $matches[4];
                 
                 // Generate a random recent timestamp (last 24 hours)
                 $timestamp = time() - rand(0, 86400);
                 $new_date = date('M d H:i:s', $timestamp);
                 
                 $entry = "$new_date $host $process: $message";
            }
        } elseif ($type == 'Apache') {
            // Format: [Sun Dec 04 04:47:44 2005] [notice] ...
            // Need to convert to: M d H:i:s Host Process: Message
            if (preg_match('/^\[[^\]]+\]\s\[([^\]]+)\]\s(.*)$/', $line, $matches)) {
                $level = $matches[1]; // notice, error
                $msg = $matches[2];
                $host = 'web-server-01';
                $process = "httpd[$level]";
                
                // Random recent timestamp
                $timestamp = time() - rand(0, 86400);
                $new_date = date('M d H:i:s', $timestamp);
                
                $entry = "$new_date $host $process: $msg";
            }
        }
        
        if ($entry) {
            $normalized_logs[] = $entry;
        }
    }
}

// Shuffle to mix
shuffle($normalized_logs);

// Write to fulllogs.log
file_put_contents('fulllogs.log', implode(PHP_EOL, $normalized_logs));
echo "Successfully imported " . count($normalized_logs) . " logs into fulllogs.log\n";
?>
