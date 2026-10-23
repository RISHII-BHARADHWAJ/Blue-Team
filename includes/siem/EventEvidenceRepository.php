<?php
/** Immutable submitted evidence, independent of external intelligence and case state. */
declare(strict_types=1);

final class EventEvidenceRepository
{
    public function __construct(private PDO $pdo) {}

    public function available(): bool
    {
        return (int)$this->pdo->query("SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = 'event_evidence'")->fetchColumn() === 1;
    }

    public function append(int $logId, array $alert, array $payload, string $fingerprint, string $actor, ?string $rawBody): int
    {
        $raw = $rawBody ?? json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        // Callers supplying bytes must supply the same parsed evidence, not unrelated JSON.
        if ($rawBody !== null && json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR) !== $payload) {
            throw new InvalidArgumentException('Submitted body does not match the parsed payload.');
        }
        $sourceTime = $payload['event_timestamp'] ?? $payload['timestamp'] ?? null;
        $stmt = $this->pdo->prepare('INSERT INTO event_evidence
            (log_id, fingerprint, source, source_type, source_event_id, submitted_by, is_simulated,
             event_timestamp, received_at, timestamp_origin, canonical_json, raw_payload, payload_encoding, payload_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([
            $logId, $fingerprint, $alert['source'], $alert['source_type'], $alert['source_event_id'],
            $actor, (int)$alert['is_simulated'], $alert['event_timestamp'], $alert['received_at'],
            $sourceTime === null || $sourceTime === '' ? 'receipt_fallback' : 'source',
            json_encode($alert, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            $raw, $rawBody === null ? 'reencoded_json' : 'http_body', hash('sha256', $raw),
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    /** Bounded, literal search. No legacy rows without provenance are included. */
    public function search(array $input, int $page = 1, int $limit = 25): array
    {
        $where = []; $params = [];
        foreach (['source'=>400, 'submitted_by'=>1020] as $key=>$maxBytes) {
            if (isset($input[$key]) && (!is_string($input[$key]) || strlen($input[$key]) > $maxBytes || !preg_match('//u', $input[$key]))) {
                throw new InvalidArgumentException('Source and submitter filters must be valid UTF-8 text within their field limits.');
            }
        }
        foreach (['source' => 'BINARY e.source', 'submitted_by' => 'BINARY e.submitted_by', 'severity' => 'l.severity', 'source_ip' => 'l.source_ip'] as $key => $column) {
            if (isset($input[$key]) && is_string($input[$key]) && $input[$key] !== '') {
                $where[] = "$column = ?";
                $params[] = $input[$key] === 'MEDIUM' && $key === 'severity' ? 'WARNING' : $input[$key];
            }
        }
        if (isset($input['kind']) && in_array($input['kind'], ['observed', 'simulated'], true)) {
            $where[] = 'e.is_simulated = ?';
            $params[] = $input['kind'] === 'simulated' ? 1 : 0;
        }
        foreach (['from' => '>=', 'to' => '<='] as $key => $operator) {
            if (!empty($input[$key]) && is_string($input[$key])) {
                $date = DateTimeImmutable::createFromFormat('!Y-m-d', $input[$key], new DateTimeZone('UTC'));
                if (!$date || $date->format('Y-m-d') !== $input[$key]) {
                    throw new InvalidArgumentException('Date filters must be valid YYYY-MM-DD dates.');
                }
                $where[] = "e.event_timestamp $operator ?";
                $params[] = $input[$key] . ($key === 'from' ? ' 00:00:00' : ' 23:59:59');
            }
        }
        if (!empty($input['q']) && is_string($input['q'])) {
            $q = '%' . strtr(substr($input['q'], 0, 200), ['!' => '!!', '%' => '!%', '_' => '!_']) . '%';
            $where[] = "(l.message LIKE ? ESCAPE '!' OR e.source_event_id LIKE ? ESCAPE '!')";
            array_push($params, $q, $q);
        }
        $sql = ' FROM event_evidence e JOIN logs l ON l.id = e.log_id' . ($where ? ' WHERE ' . implode(' AND ', $where) : '');
        $stmt = $this->pdo->prepare('SELECT COUNT(*)' . $sql);
        $stmt->execute($params);
        $total = (int)$stmt->fetchColumn();
        $limit = max(1, min(100, $limit));
        $pages = max(1, (int)ceil($total / $limit));
        $page = max(1, min($pages, $page));
        $stmt = $this->pdo->prepare('SELECT e.id, e.log_id, e.source, e.source_type, e.source_event_id, e.submitted_by,
            e.is_simulated, e.event_timestamp, e.received_at, e.timestamp_origin,
            l.source_ip, l.severity, l.category, l.message' . $sql . ' ORDER BY e.received_at DESC, e.id DESC LIMIT ? OFFSET ?');
        foreach ($params as $i => $value) $stmt->bindValue($i + 1, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
        $stmt->bindValue(count($params) + 1, $limit, PDO::PARAM_INT);
        $stmt->bindValue(count($params) + 2, ($page - 1) * $limit, PDO::PARAM_INT);
        $stmt->execute();
        return ['rows' => $stmt->fetchAll(PDO::FETCH_ASSOC), 'total' => $total, 'page' => $page, 'pages' => $pages];
    }

    public function findByLogId(int $logId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT e.*, l.source_ip, l.severity, l.category, l.message
            FROM event_evidence e JOIN logs l ON l.id = e.log_id WHERE e.log_id = ?');
        $stmt->execute([$logId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;
        $stmt = $this->pdo->prepare('SELECT i.id, i.incident_number, i.status, ia.correlation_rule
            FROM incident_alerts ia JOIN incidents i ON i.id = ia.incident_id WHERE ia.log_id = ? ORDER BY i.id');
        $stmt->execute([$logId]);
        $row['incidents'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $row;
    }
}
