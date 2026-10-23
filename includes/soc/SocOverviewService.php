<?php
declare(strict_types=1);

/** Read-only overview: evidence, case workload and external intelligence stay separate. */
final class SocOverviewService {
    public function __construct(private PDO $pdo) {}

    public function build(): array {
        $result = ['as_of_utc'=>null, 'evidence'=>null, 'incidents'=>null, 'intelligence'=>null, 'errors'=>[]];
        $own = !$this->pdo->inTransaction();
        try {
            if ($own) {
                $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
                $this->pdo->beginTransaction();
            }
            $clock = $this->pdo->query('SELECT UTC_TIMESTAMP() AS utc_now, NOW() AS record_now')->fetch(PDO::FETCH_ASSOC);
            $result['as_of_utc'] = $clock['utc_now'];
            $utcNow = $this->pdo->quote($clock['utc_now']);
            $recordNow = $this->pdo->quote($clock['record_now']);
            // A broken or missing section must not turn into a plausible zero metric.
            foreach (['evidence','incidents','intelligence'] as $section) {
                try {
                    $result[$section] = match ($section) {
                        'evidence'=>$this->evidence($utcNow),
                        'incidents'=>$this->incidents($recordNow),
                        'intelligence'=>$this->intelligence(),
                    };
                } catch (Throwable $e) {
                    error_log('SOC overview '.$section.' unavailable: '.$e->getMessage());
                    $result['errors'][] = $section;
                }
            }
            if ($own) $this->pdo->commit();
        } catch (Throwable $e) {
            if ($own && $this->pdo->inTransaction()) $this->pdo->rollBack();
            error_log('SOC overview unavailable: '.$e->getMessage());
            return ['as_of_utc'=>null, 'evidence'=>null, 'incidents'=>null, 'intelligence'=>null,
                'errors'=>['evidence','incidents','intelligence']];
        }
        return $result;
    }

    private function evidence(string $utcNow): array {
        $from = ' FROM event_evidence e JOIN logs l ON l.id=e.log_id WHERE e.is_simulated=0';
        $summary = $this->pdo->query("SELECT COUNT(*) AS total,
            COUNT(DISTINCT NULLIF(l.source_ip,'')) AS source_ips,
            COALESCE(SUM(e.received_at >= DATE_SUB($utcNow, INTERVAL 1 DAY) AND e.received_at <= $utcNow),0) AS received_24h,
            MAX(e.received_at) AS last_received_at".$from)->fetch(PDO::FETCH_ASSOC);
        foreach (['total','source_ips','received_24h'] as $key) $summary[$key] = (int)$summary[$key];
        $summary['severities'] = $this->pdo->query('SELECT COALESCE(l.severity,\'UNKNOWN\') AS severity, COUNT(*) AS n'.$from.
            " GROUP BY l.severity ORDER BY FIELD(l.severity,'CRITICAL','HIGH','WARNING','INFO','LOW'), l.severity")->fetchAll(PDO::FETCH_ASSOC);
        $summary['recent'] = $this->pdo->query('SELECT e.id, e.log_id, e.source, e.source_type, e.event_timestamp, e.received_at,
            l.source_ip, l.severity, LEFT(l.message,500) AS message, CHAR_LENGTH(l.message)>500 AS message_truncated'.$from.
            ' ORDER BY e.received_at DESC,e.id DESC LIMIT 12')->fetchAll(PDO::FETCH_ASSOC);
        return $summary;
    }

    private function incidents(string $recordNow): array {
        $from = " FROM incidents WHERE is_simulated=0 AND status IN ('NEW','OPEN','INVESTIGATING','CONTAINED')";
        $summary = $this->pdo->query("SELECT COUNT(*) AS active, COALESCE(SUM(assigned_to IS NULL),0) AS unassigned,
            COALESCE(SUM(priority='P1'),0) AS p1,
            COALESCE(SUM(updated_at <= DATE_SUB($recordNow, INTERVAL 7 DAY)),0) AS unchanged_7d".$from)->fetch(PDO::FETCH_ASSOC);
        foreach ($summary as $key=>$value) $summary[$key] = (int)$value;
        $summary['rows'] = $this->pdo->query('SELECT id, incident_number, title, severity, status, priority, assigned_to, updated_at'.$from.
            " ORDER BY FIELD(priority,'P1','P2','P3','P4'), created_at ASC,id ASC LIMIT 6")->fetchAll(PDO::FETCH_ASSOC);
        return $summary;
    }

    private function intelligence(): array {
        $summary = $this->pdo->query('SELECT COUNT(*) AS listings, COUNT(DISTINCT provider) AS providers,
            MAX(fetched_at) AS last_fetched_at FROM threat_feed_indicators')->fetch(PDO::FETCH_ASSOC);
        $summary['listings'] = (int)$summary['listings'];
        $summary['providers'] = (int)$summary['providers'];
        return $summary;
    }
}
