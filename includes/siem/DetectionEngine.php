<?php
/** Fixed, typed rules over accepted evidence. No executable user-supplied rules. */
declare(strict_types=1);
final class DetectionEngine
{
    public function __construct(private PDO $pdo) {}

    /** Lock in a stable order BEFORE ingestion. Serializes evaluation and config edits.
     * Deliberate small-deployment tradeoff: prevents missed simultaneous thresholds
     * and duplicate findings; locks last only for this database transaction.
     */
    public function lockRules(): array
    {
        if (!$this->pdo->inTransaction()) throw new LogicException('Detection evaluation requires a transaction.');
        return $this->pdo->query('SELECT * FROM detection_rules ORDER BY rule_key FOR UPDATE')->fetchAll(PDO::FETCH_ASSOC);
    }

    public static function isAuthFailure(array $alert): bool
    {
        $metadata = $alert['metadata'] ?? [];
        return is_array($metadata) && ($metadata['event_type'] ?? null) === 'authentication'
            && ($metadata['outcome'] ?? null) === 'failure' && !empty($alert['source_ip']);
    }

    public static function groupKey(array $alert, string $actor): string
    {
        return hash('sha256', json_encode([$actor, $alert['source'], $alert['source_type'],
            $alert['source_ip'], (bool)$alert['is_simulated']], JSON_THROW_ON_ERROR));
    }

    /** Called once per newly accepted event, in the ingestion transaction. */
    public function evaluate(array $rules, array $alert, int $evidenceId, string $actor, array $intel): array
    {
        if (!$this->pdo->inTransaction()) throw new LogicException('Detection evaluation requires a transaction.');
        $group = self::groupKey($alert, $actor);
        $now = $alert['received_at'];
        $authFailure = self::isAuthFailure($alert);
        if ($authFailure) {
            $stmt = $this->pdo->prepare('INSERT INTO detection_observations (evidence_id, group_key, received_at) VALUES (?, ?, ?)');
            $stmt->execute([$evidenceId, $group, $now]);
        }
        $findings = [];
        foreach ($rules as $rule) {
            if (!(bool)$rule['enabled']) continue;
            $key = $rule['rule_key'];
            if ($key === 'auth_failures' && !$authFailure) continue;
            if ($key === 'source_ip_intel' && !$intel) continue;
            if (!in_array($key, ['auth_failures', 'source_ip_intel'], true)) continue;
            $since = (new DateTimeImmutable($now, new DateTimeZone('UTC')))
                ->modify('-' . (int)$rule['window_seconds'] . ' seconds')->format('Y-m-d H:i:s');
            // A current locking read remains correct even under an outer repeatable-read snapshot.
            $stmt = $this->pdo->prepare('SELECT id FROM detection_findings WHERE rule_key = ?
                AND rule_revision = ? AND group_key = ? AND created_at > ? ORDER BY id DESC LIMIT 1 FOR UPDATE');
            $stmt->execute([$key, $rule['revision'], $group, $since]);
            if ($stmt->fetchColumn()) continue;
            $ids = [$evidenceId];
            $context = ['source'=>$alert['source'], 'source_type'=>$alert['source_type'],
                'submitted_by'=>$actor, 'source_ip'=>$alert['source_ip'], 'window_basis'=>'receipt_utc',
                'window_start_exclusive'=>$since, 'window_end_inclusive'=>$now];
            if ($key === 'auth_failures') {
                $stmt = $this->pdo->prepare('SELECT evidence_id FROM detection_observations
                    WHERE group_key = ? AND received_at > ? AND received_at <= ?
                    ORDER BY received_at DESC, evidence_id DESC LIMIT ? FOR UPDATE');
                $stmt->bindValue(1, $group); $stmt->bindValue(2, $since); $stmt->bindValue(3, $now);
                $stmt->bindValue(4, (int)$rule['threshold_count'], PDO::PARAM_INT); $stmt->execute();
                $ids = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
                if (count($ids) < (int)$rule['threshold_count']) continue;
                $summary = 'At least ' . count($ids) . ' reported authentication failures within ' . $rule['window_seconds'] . ' seconds.';
                $context['evidence_selection'] = 'Most recent threshold_count failures; not the full window count.';
            } else {
                $summary = 'Reported source IP appears in external intelligence; investigate, not confirmation of compromise.';
                $context['intelligence_matches'] = $intel;
            }
            $stmt = $this->pdo->prepare('INSERT INTO detection_findings
                (rule_key, rule_revision, group_key, trigger_evidence_id, is_simulated, severity,
                 summary, rule_snapshot, context_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
            $stmt->execute([$key, $rule['revision'], $group, $evidenceId, (int)$alert['is_simulated'],
                $rule['severity'], $summary, json_encode($rule, JSON_THROW_ON_ERROR),
                json_encode($context, JSON_THROW_ON_ERROR), $now]);
            $id = (int)$this->pdo->lastInsertId();
            $stmt = $this->pdo->prepare('INSERT INTO detection_finding_evidence (finding_id, evidence_id) VALUES (?, ?)');
            foreach ($ids as $supportId) $stmt->execute([$id, $supportId]);
            $findings[] = ['id'=>$id, 'rule_key'=>$key, 'severity'=>$rule['severity'],
                'is_simulated'=>(bool)$alert['is_simulated'], 'evidence_ids'=>$ids];
        }
        return $findings;
    }

    public function linkIncident(array $findings, ?int $incidentId): void
    {
        if ($incidentId === null) return;
        $stmt = $this->pdo->prepare('UPDATE detection_findings SET incident_id = ? WHERE id = ? AND is_simulated = 0');
        foreach ($findings as $finding) $stmt->execute([$incidentId, $finding['id']]);
    }
}
