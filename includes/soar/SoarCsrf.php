<?php
/**
 * CSRF guard for state-changing SOAR REST endpoints.
 *
 * Browser sessions must send the token issued by the dashboard in the
 * X-CSRF-Token header (or a csrf_token form field). API automation authenticated
 * with the configured Bearer token is not cookie-authenticated and is exempt.
 *
 * Call only after SoarAuth::getContext() has resolved the caller.
 */
final class SoarCsrf
{
    public static function enforce(array $auth): void
    {
        if (($auth['actor'] ?? '') === 'api_automation') {
            return;
        }

        $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? null);
        $expected = $_SESSION['csrf_token'] ?? null;

        if (!is_string($provided) || $provided === '' ||
            !is_string($expected) || $expected === '' ||
            !hash_equals($expected, $provided)) {
            http_response_code(403);
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode([
                'success' => false,
                'error' => 'csrf_verification_failed',
                'message' => 'Missing or invalid CSRF token.'
            ]);
            exit;
        }
    }
}
