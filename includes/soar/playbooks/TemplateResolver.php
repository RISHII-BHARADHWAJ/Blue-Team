<?php
/**
 * ThreatPulse SOAR - Template Resolver
 *
 * Resolves safe {{namespace.field}} template variables from an immutable
 * PlaybookContext. ZERO support for arbitrary expressions, method calls,
 * PHP, SQL, shell metacharacters, or property traversal outside the allowlist.
 *
 * Any template variable not in the allowlist causes a ValidationException.
 */
class TemplateResolver {

    // Explicit allowlist of resolvable template variables.
    // Dot-notation: {{namespace.field}}
    private static array $ALLOWLIST = [
        // Incident fields
        'incident.id',
        'incident.incident_number',
        'incident.title',
        'incident.description',
        'incident.severity',
        'incident.status',
        'incident.priority',
        'incident.risk_score',
        'incident.attack_category',
        'incident.source_ip',
        // IOC fields (uses first attached IOC)
        'ioc.value',
        'ioc.type',
        'ioc.assessment',
        // Analyst / actor fields
        'analyst.id',
        'analyst.username',
        // Run fields
        'run.run_uuid',
        'run.mode',
    ];

    /** Resolve all {{var}} tokens in a string using the provided context snapshot. */
    public function resolve(string $template, array $context): string {
        $this->validateTemplateTokens($template);

        return preg_replace_callback(
            '/\{\{([a-z_][a-z0-9_.]*)\}\}/i',
            function (array $m) use ($context): string {
                $key = strtolower($m[1]);
                [$ns, $field] = explode('.', $key, 2) + [1 => ''];
                return (string)($context[$ns][$field] ?? '');
            },
            $template
        );
    }

    /**
     * Validate that every {{...}} token in the template is on the allowlist.
     * Reject on first unknown variable.
     *
     * @throws RuntimeException on unknown or dangerous template variable
     */
    public function validateTemplateTokens(string $template): void {
        preg_match_all('/\{\{(.+?)\}\}/s', $template, $matches);
        foreach ($matches[1] as $raw) {
            $token = strtolower(trim($raw));

            // Reject multi-line tokens (potential injection)
            if (str_contains($raw, "\n") || str_contains($raw, "\r")) {
                throw new RuntimeException("Template variable contains illegal newline: {{{$raw}}}");
            }
            // Reject tokens with shell, PHP, SQL metacharacters
            if (preg_match('/[;\(\)\[\]\$`\'\"\\\\|&<>]/', $token)) {
                throw new RuntimeException("Template variable contains forbidden metacharacters: {{{$raw}}}");
            }
            // Reject tokens with method-call syntax
            if (str_contains($token, '(') || str_contains($token, ')')) {
                throw new RuntimeException("Template method call syntax is forbidden: {{{$raw}}}");
            }
            // Check allowlist
            if (!in_array($token, self::$ALLOWLIST, true)) {
                throw new RuntimeException("Unknown template variable: {{{$raw}}} — only allowlisted variables are permitted.");
            }
        }
    }

    /** Validate all template values inside a parameters array (recursively). */
    public function validateParameterTemplates(array $parameters): array {
        $errors = [];
        array_walk_recursive($parameters, function ($value) use (&$errors) {
            if (!is_string($value)) return;
            try {
                $this->validateTemplateTokens($value);
            } catch (RuntimeException $e) {
                $errors[] = $e->getMessage();
            }
        });
        return $errors;
    }

    public static function getAllowedVariables(): array {
        return self::$ALLOWLIST;
    }
}
