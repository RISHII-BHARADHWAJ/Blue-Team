<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/intel/FeedCatalog.php';
function parserCheck(bool $ok,string $label): void { if (!$ok) throw new RuntimeException($label); echo "PASS: $label\n"; }
try {
    $r=FeedCatalog::parse('emerging_threats',"# public listings\n8.8.8.8\n8.8.8.8\n10.0.0.1\nnot-an-ip\n2001:4860:4860:0:0:0:0:8888\n2001:4860:4860::8888\n");
    parserCheck(count($r['rows'])===2 && $r['duplicates']===2 && $r['invalid']===2,'canonical deduplication and public-IP validation');
    $zone=date_default_timezone_get(); date_default_timezone_set('Asia/Kolkata');
    $r=FeedCatalog::parse('feodo_tracker','[{"ip_address":"8.8.8.8","malware":"Example","port":443,"first_seen":"2026-10-21 10:00:00","last_online":"2026-10-21T17:30:00+05:30"}]');
    parserCheck($r['rows'][0]['first']==='2026-10-21 10:00:00' && $r['rows'][0]['last']==='2026-10-21 12:00:00','source times interpreted as UTC or explicit offset independent of server timezone');
    date_default_timezone_set($zone);
    $r=FeedCatalog::parse('feodo_tracker','{"blocklist":[{"ip":"8.8.8.8","first_seen":"yesterday","last_online":"2026-02-30","port":999999}]}');
    parserCheck($r['rows'][0]['first']===null && $r['rows'][0]['last']===null && $r['rows'][0]['port']===null && $r['rows'][0]['malware']===null,'missing or invalid metadata is not fabricated');
    foreach (['[]','{"data":[]}'] as $raw) parserCheck(FeedCatalog::parse('feodo_tracker',$raw)['rows']===[],'explicit empty Feodo array accepted');
    foreach (['{}','{"data":{}}','null','broken','{"error":"unavailable"}'] as $raw) {
        $bad=false; try { FeedCatalog::parse('feodo_tracker',$raw); } catch (UnexpectedValueException $e) { $bad=true; }
        parserCheck($bad,'malformed or object-only JSON rejected');
    }
    $bad=false; try { FeedCatalog::parse('cins_army','<html>Service unavailable</html>'); } catch (UnexpectedValueException $e) { $bad=true; }
    parserCheck($bad,'HTML error page is not a successful empty import');
    $lines=[]; for($i=0;$i<2001;$i++) $lines[]='11.'.intdiv($i,65536).'.'.(intdiv($i,256)%256).'.'.($i%256);
    $r=FeedCatalog::parse('cins_army',implode("\n",$lines));
    parserCheck(count($r['rows'])===2000 && $r['truncated'],'cap explicitly reports incomplete import');
    $bad=false; try { FeedCatalog::parse('cins_army',str_repeat('x',FeedCatalog::MAX_BYTES+1)); } catch (UnexpectedValueException $e) { $bad=true; }
    parserCheck($bad,'oversize response rejected before parsing');
    $bad=false; try { FeedCatalog::get('http://localhost'); } catch (InvalidArgumentException $e) { $bad=true; }
    parserCheck($bad,'arbitrary feed URL cannot be selected');
} catch (Throwable $e) { fwrite(STDERR,'FAIL: '.$e->getMessage()."\n"); exit(1); }
