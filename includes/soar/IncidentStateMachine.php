<?php
/**
 * ThreatPulse SOAR - Incident State Machine
 * 
 * Enforces valid lifecycle status transitions for security incidents:
 * 
 * Valid Transitions:
 * - NEW           -> OPEN, CLOSED
 * - OPEN          -> INVESTIGATING, CLOSED
 * - INVESTIGATING -> CONTAINED, RESOLVED, CLOSED
 * - CONTAINED     -> RESOLVED, CLOSED
 * - RESOLVED      -> CLOSED
 * - CLOSED        -> (Terminal State: No transitions allowed)
 */

class InvalidStateTransitionException extends RuntimeException {}

class IncidentStateMachine {

    public const STATE_NEW           = 'NEW';
    public const STATE_OPEN          = 'OPEN';
    public const STATE_INVESTIGATING = 'INVESTIGATING';
    public const STATE_CONTAINED     = 'CONTAINED';
    public const STATE_RESOLVED      = 'RESOLVED';
    public const STATE_CLOSED        = 'CLOSED';

    /**
     * All recognized incident states.
     */
    public const STATES = [
        self::STATE_NEW,
        self::STATE_OPEN,
        self::STATE_INVESTIGATING,
        self::STATE_CONTAINED,
        self::STATE_RESOLVED,
        self::STATE_CLOSED,
    ];

    /**
     * State transition matrix: key = current state, value = array of permitted next states.
     */
    private const TRANSITIONS = [
        self::STATE_NEW => [
            self::STATE_OPEN,
            self::STATE_CLOSED,
        ],
        self::STATE_OPEN => [
            self::STATE_INVESTIGATING,
            self::STATE_CLOSED,
        ],
        self::STATE_INVESTIGATING => [
            self::STATE_CONTAINED,
            self::STATE_RESOLVED,
            self::STATE_CLOSED,
        ],
        self::STATE_CONTAINED => [
            self::STATE_RESOLVED,
            self::STATE_CLOSED,
        ],
        self::STATE_RESOLVED => [
            self::STATE_CLOSED,
        ],
        self::STATE_CLOSED => [
            // Terminal state: No outgoing transitions in Phase 3
        ],
    ];

    /**
     * Active states that can receive correlated alerts.
     */
    public const ACTIVE_STATES = [
        self::STATE_NEW,
        self::STATE_OPEN,
        self::STATE_INVESTIGATING,
        self::STATE_CONTAINED,
    ];

    /**
     * Check if a state transition from $from to $to is valid.
     */
    public static function canTransition(string $from, string $to): bool {
        $fromUpper = strtoupper(trim($from));
        $toUpper = strtoupper(trim($to));

        if (!in_array($fromUpper, self::STATES, true) || !in_array($toUpper, self::STATES, true)) {
            return false;
        }

        if ($fromUpper === $toUpper) {
            return true; // No-op transition is allowed
        }

        $allowed = self::TRANSITIONS[$fromUpper] ?? [];
        return in_array($toUpper, $allowed, true);
    }

    /**
     * Assert that a transition is valid or throw an exception.
     * 
     * @throws InvalidStateTransitionException
     */
    public static function assertValidTransition(string $from, string $to): void {
        $fromUpper = strtoupper(trim($from));
        $toUpper = strtoupper(trim($to));

        if (!self::canTransition($fromUpper, $toUpper)) {
            throw new InvalidStateTransitionException(
                "Invalid incident state transition from '{$fromUpper}' to '{$toUpper}'."
            );
        }
    }

    /**
     * Check if a status represents an active, correlatable incident.
     */
    public static function isActive(string $status): bool {
        return in_array(strtoupper(trim($status)), self::ACTIVE_STATES, true);
    }
}
