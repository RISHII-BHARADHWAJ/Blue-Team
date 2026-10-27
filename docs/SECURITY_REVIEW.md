# Application security review

This is a source review and automated regression assessment of the local ThreatPulse lab. It is not a penetration-test certification or a guarantee against every attack. OWASP ASVS 5.0 provides the reference categories: https://owasp.org/www-project-application-security-verification-standard/.

## Changes and regression coverage

| Area | Finding and protection | Verification |
| --- | --- | --- |
| Sessions | Inconsistent cookie settings and no enforced lifetime; shared session setup now enforces HttpOnly, SameSite Strict, cookie-only IDs, 30-minute idle and 8-hour absolute expiry | PHP expiry tests; HTTP cookie assertions |
| Authorization | Cached roles could survive demotion; real login sessions now refresh role and account existence from the database | Database regression demotes and deletes a test account |
| Login abuse | Short rate-limit windows could delete longer login windows; concurrent read/increment could lose attempts | Atomic per-key increments, window isolation regression; atomic failed-login increments |
| Malformed requests | Array-shaped credentials/CSRF fields could cause PHP exceptions | HTTP and PHP malformed-input tests |
| XSS | Simulated terminal echoed input through innerHTML | Plain-text DOM insertion and a browser image/onerror regression |
| CSRF | GET logout changed session state | GET confirmation; POST requires valid CSRF; HTTP rejection test |
| SSRF | Incomplete IPv6/CGNAT checks, DNS re-resolution, unbounded stream fallback and late response-size check | Public-address restrictions, pinned cURL resolution, no redirects/proxies/fallback, streaming cap; deterministic blocked-IP/URL tests |
| Files and errors | Git/dotfiles and alternate source/backup names could be served; PHP errors could disclose internals | Apache deny rules and 1 MiB request limit; PHP error-display disabled; HTTP file/body-limit checks |
| Network exposure | Compose published to every network interface | Default binds to 127.0.0.1:8080 |

The existing CI suites additionally exercise SQL parameterization/injection handling, authenticated and anonymous routes, role restrictions, object ownership for notifications, evidence rendering, CSRF, tampering with approval data, concurrent mutations, playbook approval boundaries, database rollback, and desktop/mobile workflows. The security suite adds a login SQL-injection payload. These are specific regression cases, not exhaustive fuzzing of every input.

## Operational implications

- Keep using http://localhost:8080 for the local lab. Remote access now requires an explicit deployment configuration.
- Sessions created before this update adopt the lifetime policy on first use. New successful logins rotate both the session identifier and CSRF token.
- HTTPS deployments behind a trusted TLS-terminating proxy must set SESSION_COOKIE_SECURE=1 in the web environment. Untrusted forwarded headers do not control cookies.
- Enrichment requires PHP cURL, now installed in the image. Rebuild the web image after pulling.
- No database migration or deletion is required. Existing data remains in its Compose volume.

## Remaining work before any public deployment

The lab still ships documented demo credentials and development database passwords. Rotate them before exposing it; changing Compose variables alone does not rotate credentials inside an existing MariaDB volume. Configure HTTPS, trusted proxy/network rules, secrets management, backups and restore testing, log retention, monitoring, and dependency/image updates. MFA and self-service session revocation are not implemented.

Legacy server-created analyst-only sessions remain supported for existing integrations/tests. Normal interactive login sessions always carry a database user ID and receive current-role/deleted-account checks. Remove the legacy session format and migrate its consumers before a production rollout.

The UI still uses inline scripts/styles and third-party CDN resources; a complete nonce-based CSP and locally pinned assets require a separate compatibility migration. Some legacy pages lack a full CSP. These are defense-in-depth gaps, not an assertion that all XSS paths have been ruled out.

This review did not execute volumetric denial-of-service attacks, scan external feed providers, audit the host OS, certify container dependencies as CVE-free, or test a deployed TLS/reverse-proxy stack. DNS pinning and response-size bounds were source-reviewed; blocked-destination cases are exercised without connecting to private or external targets. Production infrastructure and independent penetration testing remain outside this local lab assessment.
