<?php
/** Case-scoped, local IOC discovery and read-only saved intelligence inspection. */
declare(strict_types=1);
require_once __DIR__.'/IncidentIocService.php';
require_once __DIR__.'/IncidentTimeline.php';
require_once __DIR__.'/SoarAuth.php';

final class IncidentIocWorkspace
{
    public function __construct(private PDO $pdo) {}

    /** Add only missing indicators/links; retries preserve existing classifications and metadata. */
    public function discover(int $incidentId, int $userId): array
    {
        if ($incidentId < 1 || $userId < 1) throw new InvalidArgumentException('A case and named analyst are required.');
        $own = !$this->pdo->inTransaction();
        $sp = 'ioc_' . bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $sp");
        try {
            $stmt = $this->pdo->prepare('SELECT username, role FROM users WHERE id = ? LOCK IN SHARE MODE');
            $stmt->execute([$userId]); $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']), 'create_incidents')) {
                throw new DomainException('A named Tier 2 or higher analyst is required to discover indicators.');
            }
            $incident = (new IncidentRepository($this->pdo))->find($incidentId, true);
            if (!$incident) throw new OutOfBoundsException('Incident not found.');
            if ($incident['is_simulated']) throw new UnexpectedValueException('Simulated cases use dry-run playbooks; discovery is disabled.');

            // Preserve canonical destination/IOC/metadata fields absent from legacy logs.
            $stmt = $this->pdo->prepare('SELECT l.id, l.source_ip, l.message, l.category,
                e.canonical_json, e.is_simulated FROM incident_alerts ia JOIN logs l ON l.id = ia.log_id
                LEFT JOIN event_evidence e ON e.log_id = l.id WHERE ia.incident_id = ? ORDER BY l.id LIMIT 1001');
            $stmt->execute([$incidentId]); $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (count($alerts) > 1000) throw new UnexpectedValueException('This case exceeds the 1,000-alert discovery limit. No indicators were changed.');
            $extractor = new IocExtractor(); $candidates = [];
            foreach ($alerts as $row) {
                if (!empty($row['is_simulated'])) throw new UnexpectedValueException('Simulated evidence cannot populate the shared IOC inventory.');
                $canonical = json_decode($row['canonical_json'] ?? '{}', true);
                $alert = $row;
                if (is_array($canonical)) {
                    foreach (['source_ip','destination_ip','ioc_type','ioc_value','message','category'] as $key) {
                        if (isset($canonical[$key]) && is_string($canonical[$key])) $alert[$key] = $canonical[$key];
                    }
                    if (is_array($canonical['metadata'] ?? null)) $alert['metadata'] = $canonical['metadata'];
                }
                foreach ($extractor->extractFromAlert($alert, false) as $item) {
                    if (strlen($item['value']) > 500) throw new UnexpectedValueException('A candidate exceeds the 500-byte indicator limit. No indicators were changed.');
                    $key = $item['type'].':'.$item['value'];
                    // Existing schema stores one role. First source in log-ID order wins deterministically.
                    if (!isset($candidates[$key])) $candidates[$key] = $item + ['role'=>IncidentIocService::determineRole($item, $alert)];
                    if (count($candidates) > 2000) throw new UnexpectedValueException('This case exceeds the 2,000-indicator discovery limit. No indicators were changed.');
                }
            }
            ksort($candidates); // Stable IOC lock order across cases.
            $newLinks = 0;
            $insert = $this->pdo->prepare('INSERT INTO iocs (ioc_type,ioc_value,source_feed) VALUES (?,?,?)
                ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)');
            $attach = $this->pdo->prepare('INSERT INTO incident_iocs (incident_id,ioc_id,role) VALUES (?,?,?)
                ON DUPLICATE KEY UPDATE id = incident_iocs.id');
            foreach ($candidates as $item) {
                $insert->execute([$item['type'], $item['value'], 'incident_'.$incidentId]);
                $iocId = (int)$this->pdo->lastInsertId();
                $attach->execute([$incidentId, $iocId, $item['role']]);
                $newLinks += $attach->rowCount() === 1 ? 1 : 0;
            }
            if ($newLinks > 0) {
                $details = ['event_subtype'=>'IOCS_DISCOVERED', 'new_links'=>$newLinks,
                    'candidate_count'=>count($candidates), 'alert_count'=>count($alerts), 'user_id'=>$userId];
                (new IncidentTimeline($this->pdo))->addEvent($incidentId, 'EVIDENCE_ATTACHED',
                    IncidentTimeline::ACTOR_ANALYST, $user['username'], "Discovered {$newLinks} new case indicators from stored alerts", $details);
                $this->pdo->prepare('INSERT INTO audit_log (analyst,ip_address,action,target,result,details,user_agent) VALUES (?,?,?,?,?,?,?)')
                    ->execute([substr($user['username'],0,50), substr($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',0,45),
                        'discover_incident_iocs', $incident['incident_number'], 'success', json_encode($details, JSON_THROW_ON_ERROR),
                        substr($_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-IOC-Workspace',0,500)]);
            }
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $sp");
            return ['new_links'=>$newLinks, 'candidate_count'=>count($candidates), 'alert_count'=>count($alerts)];
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $sp"); $this->pdo->exec("RELEASE SAVEPOINT $sp"); }
            }
            throw $e;
        }
    }

    public function read(int $incidentId, int $page = 1, ?int $iocId = null, int $historyPage = 1, string $type = ''): array
    {
        $incident = (new IncidentRepository($this->pdo))->find($incidentId);
        if (!$incident) throw new OutOfBoundsException('Incident not found.');
        if ($type !== '' && !in_array($type, IocNormalizer::SUPPORTED_TYPES, true)) throw new InvalidArgumentException('Unsupported indicator type.');
        $where = 'ii.incident_id = ?'; $params = [$incidentId];
        if ($type !== '') { $where .= ' AND i.ioc_type = ?'; $params[] = $type; }
        $join = ' FROM incident_iocs ii JOIN iocs i ON i.id = ii.ioc_id WHERE '.$where;
        $stmt = $this->pdo->prepare('SELECT COUNT(*)'.$join); $stmt->execute($params);
        $pagination = $this->pagination((int)$stmt->fetchColumn(), $page);
        $stmt = $this->pdo->prepare('SELECT i.*, ii.role, ii.discovered_at'.$join.' ORDER BY ii.id DESC LIMIT 25 OFFSET ?');
        foreach ($params as $index=>$value) $stmt->bindValue($index+1, $value);
        $stmt->bindValue(count($params)+1, ($pagination['page']-1)*25, PDO::PARAM_INT); $stmt->execute();
        $iocs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($iocs as &$ioc) $ioc['intelligence'] = $this->intelligence((int)$ioc['id']);
        unset($ioc);
        $selected = null; $history = []; $historyPagination = $this->pagination(0,1);
        if ($iocId !== null) {
            $stmt = $this->pdo->prepare('SELECT i.*, ii.role, ii.discovered_at FROM incident_iocs ii JOIN iocs i ON i.id = ii.ioc_id
                WHERE ii.incident_id = ? AND ii.ioc_id = ?');
            $stmt->execute([$incidentId, $iocId]); $selected = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$selected) throw new OutOfBoundsException('Indicator not found for this incident.');
            $selected['intelligence'] = $this->intelligence($iocId);
            $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM enrichment_results WHERE ioc_id = ?'); $stmt->execute([$iocId]);
            $historyPagination = $this->pagination((int)$stmt->fetchColumn(), $historyPage);
            $stmt = $this->pdo->prepare('SELECT id, provider, status, parsed_summary, created_at, cached_until,
                cached_until > NOW() AS is_fresh FROM enrichment_results WHERE ioc_id = ? ORDER BY created_at DESC, id DESC LIMIT 25 OFFSET ?');
            $stmt->bindValue(1, $iocId, PDO::PARAM_INT); $stmt->bindValue(2, ($historyPagination['page']-1)*25, PDO::PARAM_INT); $stmt->execute();
            $history = array_map([$this,'safeResult'], $stmt->fetchAll(PDO::FETCH_ASSOC));
        }
        return compact('incident','iocs','selected','pagination','history','historyPagination','type');
    }

    /** Latest result wins even when it failed or expired; no fallback to earlier success. */
    private function intelligence(int $iocId): array
    {
        $stmt = $this->pdo->prepare('SELECT e.id, e.provider, e.status, e.parsed_summary, e.created_at, e.cached_until,
            e.cached_until > NOW() AS is_fresh FROM enrichment_results e WHERE e.ioc_id = ?
            AND NOT EXISTS (SELECT 1 FROM enrichment_results n WHERE n.ioc_id = e.ioc_id AND n.provider = e.provider
                AND (n.created_at > e.created_at OR (n.created_at = e.created_at AND n.id > e.id)))
            ORDER BY e.provider LIMIT 101');
        $stmt->execute([$iocId]); $rows = $stmt->fetchAll(PDO::FETCH_ASSOC); $limited = count($rows)>100;
        $providers = array_map([$this,'safeResult'], array_slice($rows,0,100));
        $malicious = false; $suspicious = false; $clean = false; $used = 0;
        foreach ($providers as $row) {
            if ($row['state'] !== 'CURRENT') continue;
            $used++;
            $malicious = $malicious || $row['reputation'] >= 75;
            $suspicious = $suspicious || $row['reputation'] >= 25;
            $clean = $clean || ($row['reputation'] === 0 && $row['confidence'] >= 80);
        }
        $assessment = $limited || !$used ? 'UNKNOWN' : ($malicious && $clean ? 'CONFLICTING' :
            ($malicious ? 'MALICIOUS' : ($suspicious ? 'SUSPICIOUS' : 'LOW_REPUTATION')));
        return ['assessment'=>$assessment, 'providers'=>$providers, 'current_count'=>$used, 'limited'=>$limited];
    }

    /** Only display a small allowlist; provider payloads and arbitrary summaries may contain secrets. */
    private function safeResult(array $row): array
    {
        $parsed = json_decode($row['parsed_summary'] ?? '{}', true);
        $valid = is_array($parsed);
        foreach (['reputation','confidence'] as $key) {
            $value = $parsed[$key] ?? null;
            if (!is_numeric($value) || $value < 0 || $value > 100) $valid = false;
        }
        $row['reputation'] = $valid ? (int)$parsed['reputation'] : null;
        $row['confidence'] = $valid ? (int)$parsed['confidence'] : null;
        $row['state'] = $row['status'] !== 'SUCCESS' ? $row['status'] : (!$row['is_fresh'] ? 'EXPIRED' : (!$valid ? 'INVALID' : 'CURRENT'));
        unset($row['parsed_summary'], $row['is_fresh']);
        return $row;
    }

    private function pagination(int $total, int $page): array
    {
        $pages = max(1, (int)ceil($total/25));
        return ['total'=>$total, 'pages'=>$pages, 'page'=>max(1,min($pages,$page))];
    }
}
