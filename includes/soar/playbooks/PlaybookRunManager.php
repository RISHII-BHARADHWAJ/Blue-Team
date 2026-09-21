<?php
/**
 * ThreatPulse SOAR - Playbook Run Manager
 *
 * Manages playbook_runs lifecycle and enforces the state machine:
 *
 *   PENDING → RUNNING
 *   PENDING → CANCELLED
 *   RUNNING → WAITING_APPROVAL | COMPLETED | FAILED | CANCELLED
 *   WAITING_APPROVAL → RUNNING | FAILED | CANCELLED
 *
 * All invalid transitions are rejected.
 */

require_once __DIR__ . '/PlaybookRepository.php';

class PlaybookRunManager {

    // Valid state transitions: current => [allowed next states]
    private const TRANSITIONS = [
        'PENDING'          => ['RUNNING', 'CANCELLED'],
        'RUNNING'          => ['WAITING_APPROVAL', 'COMPLETED', 'FAILED', 'CANCELLED'],
        'WAITING_APPROVAL' => ['RUNNING', 'FAILED', 'CANCELLED'],
        'COMPLETED'        => [],
        'FAILED'           => [],
        'CANCELLED'        => [],
    ];

    private PlaybookRepository $repo;
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo  = $pdo;
        $this->repo = new PlaybookRepository($pdo);
    }

    /**
     * Create a new run record.
     * @throws RuntimeException if playbook/incident not found
     */
    public function createRun(int $playbookId, ?int $incidentId, string $mode, ?int $analystId, ?int $playbookVersion = null): array {
        $uuid = bin2hex(random_bytes(16));
        $triggeredBy = ($analystId !== null) ? 'ANALYST' : 'AUTOMATION';
        $execContext = ['mode' => strtoupper($mode), 'dry_run' => (strtoupper($mode) === 'DRY_RUN')];

        $runId = $this->repo->createRun($playbookId, $incidentId, $triggeredBy, $analystId, $uuid, $execContext, $playbookVersion);
        return ['id' => $runId, 'run_uuid' => $uuid, 'status' => 'PENDING', 'playbook_version' => $playbookVersion];
    }

    /**
     * Attempt a state transition. Throws on invalid transition.
     */
    public function transition(int $runId, string $toStatus, ?string $errorMessage = null, ?int $currentStep = null): void {
        $run = $this->repo->findRun($runId);
        if (!$run) {
            throw new InvalidArgumentException("Playbook run #{$runId} not found.");
        }
        $from = $run['status'];
        $allowed = self::TRANSITIONS[$from] ?? [];
        if (!in_array($toStatus, $allowed, true)) {
            throw new RuntimeException("Invalid state transition: {$from} → {$toStatus}.");
        }
        $this->repo->updateRunStatus($runId, $toStatus, $errorMessage, $currentStep);
    }

    /**
     * Check if a transition is permitted without executing it.
     */
    public function isTransitionAllowed(string $fromStatus, string $toStatus): bool {
        return in_array($toStatus, self::TRANSITIONS[$fromStatus] ?? [], true);
    }

    public function getTransitions(): array {
        return self::TRANSITIONS;
    }

    /**
     * Acquire execution lock using DB status check.
     * Returns false if run is already RUNNING (concurrency guard).
     */
    public function acquireLock(int $runId): bool {
        if (!$this->pdo) return true; // test mode
        $stmt = $this->pdo->prepare("
            UPDATE playbook_runs SET status = 'RUNNING'
            WHERE id = ? AND status = 'PENDING'
        ");
        $stmt->execute([$runId]);
        return $stmt->rowCount() === 1; // Only 1 writer wins
    }
}
