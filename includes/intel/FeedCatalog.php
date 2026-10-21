<?php
declare(strict_types=1);
/** Fixed public endpoints; database settings never accept URLs or credentials. */
final class FeedCatalog
{
    public const FEEDS = [
        'feodo_tracker'=>['name'=>'Feodo Tracker', 'url'=>'https://feodotracker.abuse.ch/downloads/ipblocklist.json', 'limit'=>300],
        'emerging_threats'=>['name'=>'Emerging Threats', 'url'=>'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'limit'=>2000],
        'cins_army'=>['name'=>'CINS Army', 'url'=>'https://cinsscore.com/list/ci-badguys.txt', 'limit'=>2000],
        'blocklist_de'=>['name'=>'Blocklist.de', 'url'=>'https://lists.blocklist.de/lists/all.txt', 'limit'=>2000],
    ];
    public const MAX_BYTES = 10485760;
    public static function get(string $provider): array
    {
        if (!isset(self::FEEDS[$provider])) throw new InvalidArgumentException('Unknown feed provider.');
        return self::FEEDS[$provider];
    }
    public static function lockName(string $database, string $provider): string
    {
        return 'tp-feed-' . substr(hash('sha256', $database . ':' . $provider), 0, 48);
    }

    /** Bounded HTTPS read; redirects rejected instead of following arbitrary endpoints. */
    public static function download(string $url): array
    {
        $context = stream_context_create(['http'=>['timeout'=>25, 'user_agent'=>'ThreatPulse-BlueTeam/1.0',
            'ignore_errors'=>true, 'follow_location'=>0], 'ssl'=>['verify_peer'=>true, 'verify_peer_name'=>true]]);
        $raw = @file_get_contents($url, false, $context, 0, self::MAX_BYTES + 1);
        $status = null;
        foreach ($http_response_header ?? [] as $header) {
            if (preg_match('~^HTTP/\S+\s+(\d{3})~', $header, $m)) $status=(int)$m[1];
        }
        return ['status'=>$status, 'body'=>$raw];
    }

    private static function sourceTime(mixed $value): ?string
    {
        if (!is_string($value) || trim($value)==='') return null;
        // Only absolute calendar dates/times, not relative text such as "yesterday".
        if (!preg_match('/^\d{4}-\d{2}-\d{2}(?:[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/D', $value)) return null;
        try {
            $time=new DateTimeImmutable($value, new DateTimeZone('UTC'));
            $errors=DateTimeImmutable::getLastErrors();
            if ($errors && ($errors['warning_count'] || $errors['error_count'])) return null;
            $utc=$time->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
            return $utc >= '1000-01-01 00:00:00' && $utc <= '9999-12-31 23:59:59' ? $utc : null;
        } catch (Exception $e) { return null; }
    }

    /** Validate before writes. Deduplicate canonically; report caps and rejected rows. */
    public static function parse(string $provider, string $raw): array
    {
        $config=self::get($provider);
        if (strlen($raw)>self::MAX_BYTES) throw new UnexpectedValueException('Feed exceeds the 10 MiB size limit.');
        $feodo=$provider==='feodo_tracker';
        if ($feodo) {
            try { $data=json_decode($raw, false, 512, JSON_THROW_ON_ERROR); }
            catch (JsonException $e) { throw new UnexpectedValueException('Invalid Feodo JSON.'); }
            $entries=is_array($data) ? $data : ($data instanceof stdClass ? ($data->blocklist ?? $data->data ?? null) : null);
            // An empty JSON object is not an explicit empty feed list.
            if (!is_array($entries) || !array_is_list($entries)) {
                throw new UnexpectedValueException('Unexpected Feodo JSON structure.');
            }
        } else { $entries=explode("\n", $raw); }
        $rows=[]; $seen=[]; $invalid=0; $duplicates=0; $truncated=false;
        foreach ($entries as $entry) {
            if ($entry instanceof stdClass) $entry=get_object_vars($entry);
            if (!$feodo) {
                $ip=trim($entry); if ($ip==='' || str_starts_with($ip, '#')) continue;
            } else { $ip=is_array($entry) ? ($entry['ip_address'] ?? $entry['ip'] ?? null) : null; }
            if (!is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { $invalid++; continue; }
            $ip=inet_ntop(inet_pton($ip));
            if (isset($seen[$ip])) { $duplicates++; continue; }
            $seen[$ip]=true;
            if (count($rows)>=$config['limit']) { $truncated=true; continue; }
            $malware=null; $port=null; $first=null; $last=null;
            if ($feodo) {
                $family=$entry['malware'] ?? $entry['malware_family'] ?? null;
                if (is_string($family) && preg_match('//u', $family)) {
                    $malware=substr($family, 0, 150);
                    while ($malware!=='' && !preg_match('//u', $malware)) $malware=substr($malware, 0, -1);
                }
                $port=filter_var($entry['port'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1,'max_range'=>65535]]) ?: null;
                $first=self::sourceTime($entry['first_seen'] ?? null);
                $last=self::sourceTime($entry['last_online'] ?? $entry['last_seen'] ?? null);
            }
            $rows[]=['ip'=>$ip,'type'=>str_contains($ip, ':')?'IPV6':'IPV4','malware'=>$malware,'port'=>$port,'first'=>$first,'last'=>$last];
        }
        if (!$rows && (!$feodo || count($entries)>0)) throw new UnexpectedValueException('Feed returned no usable public IP addresses.');
        return ['rows'=>$rows,'invalid'=>$invalid,'duplicates'=>$duplicates,'truncated'=>$truncated];
    }
}
