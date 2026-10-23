<?php
declare(strict_types=1);

/** Read-only queue inputs, shared with integration tests. */
final class IncidentQueueQuery {
    public const STATUSES = ['NEW','OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED'];
    public const SEVERITIES = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

    public static function parse(array $input, ?int $userId): array {
        foreach (['status','severity','priority'] as $key) {
            if (is_string($input[$key] ?? null)) $input[$key] = strtoupper(trim($input[$key]));
        }
        $choice = static function(string $key, array $allowed, string $default = '') use ($input): string {
            $value = $input[$key] ?? $default;
            return is_string($value) && in_array($value, $allowed, true) ? $value : $default;
        };
        $q = $input['q'] ?? '';
        if (!is_string($q) || strlen($q) > 200) throw new InvalidArgumentException('Search must be text of at most 200 bytes.');
        $owner = $choice('owner', ['any','mine','unassigned'], 'any');
        // Keep bookmarked links from the original queue working.
        if (!isset($input['owner']) && ($input['mine'] ?? '') === '1') $owner = 'mine';
        if ($owner === 'mine' && (!$userId || $userId < 1)) throw new InvalidArgumentException('Assigned to me requires a named user session.');
        $query = [
            'q'=>trim($q), 'kind'=>$choice('kind', ['observed','simulated','all'], 'observed'),
            'status'=>$choice('status', self::STATUSES), 'severity'=>$choice('severity', self::SEVERITIES),
            'priority'=>$choice('priority', ['P1','P2','P3','P4']),
            'lifecycle'=>$choice('lifecycle', ['all','active','finished'], 'all'),
            'owner'=>$owner, 'stale_days'=>$choice('stale_days', ['1','3','7','30']),
            'sort'=>$choice('sort', ['priority','newest','oldest','least_updated'], 'priority'),
        ];
        $filters = $query;
        if ($owner === 'mine') $filters['assigned_to'] = $userId;
        if ($owner === 'unassigned') $filters['unassigned'] = true;
        $page = filter_var($input['page'] ?? 1, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;
        return ['query'=>$query, 'filters'=>$filters, 'page'=>$page];
    }
}
