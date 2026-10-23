# Personal analyst notification inbox

Open **My inbox** from the SOC overview, incident queue, or approval control-plane notification popup. `notifications.php` shows saved in-app messages for the signed-in named account, with unread/all/read filters, 25 messages per page, unread count, simulation labels and validated links to related cases, runs and approvals.

Opening the inbox or following its case links does not acknowledge notifications. Use **Mark read** on a message, or select messages on the current page and choose **Mark selected read**. Bulk acknowledgement is limited to 25 submitted IDs and never sweeps in messages that arrive later. There is no deletion or external delivery operation.

## Identity and ownership

A personal inbox requires a named session backed by an existing database user. Anonymous requests, unnamed sessions and bearer-only automation cannot access one. There is no fallback to account 1 and no administrator impersonation override. The API retains its `user_id` query parameter only for the current user's own ID; another ID is rejected.

`recipient_id` is the authoritative owner. Migration 005 added `user_id` with a default of 1, so historical records can have inconsistent values. The old `user_id OR recipient_id` condition could expose another recipient's message to the default user. Reads, counts and acknowledgement now all use `recipient_id`. No historical data is rewritten and no migration is required.

The in-app channel writes both identity columns consistently and fills both the modern type and legacy `notification_type` column. The allowlisted `NOTIFY_ANALYST` action uses this channel, records its run context and reports persistence failure honestly. Dry-run behavior still saves no notification. The inbox does not invent notifications for workflows that do not currently emit them.

## Acknowledgement and API behavior

`GET /api/v1/notifications.php` preserves the control-plane response shape (`success`, `user_id`, `unread_count`, `count`, `data`) and adds pagination. It accepts `unread_only=0|1`, `page`, and `limit` (1–100). The control-plane dropdown continues requesting ten unread notifications.

`POST /api/v1/notifications.php` accepts `notification_id` plus an optional form CSRF token; JSON callers send `X-CSRF-Token`. Named sessions always require CSRF, even if their display name is `api_automation`. Other client fields are rejected. Repeated acknowledgement returns success while preserving the first read timestamp. An unavailable or foreign ID returns 404.

The inbox's form POST supports either a single ID or a batch. The batch validates every recipient under row locks before changing anything. Mixed-owner or missing-ID batches fail atomically; callers' existing transactions are preserved using savepoints. Existing already-read rows with missing legacy read timestamps remain unchanged.

Both surfaces are no-store. API responses retain JSON content type and avoid the legacy HTML authentication-header include. The control-plane popup now links to the inbox instead of offering a no-op “Mark Read” button, checks acknowledgement responses before closing, refreshes its unread count after success, and accepts validated approval detail links.

## Display and context

HTML text is escaped. The existing secret-pattern redactor is applied on write and again on read for legacy notifications; it is not a guarantee against every possible secret format. Case/run/approval links are reconstructed from database joins. Missing or inconsistent context yields no misleading link. Simulated cases are labeled. Read state records acknowledgement only, not approval or response execution. Timestamps use server time.

## Validation

Compose CI covers recipient isolation despite conflicting legacy identity columns, admin/self-only access, named-account requirements, redaction, read timestamp stability, batch bounds and atomic rejection, later-arrival preservation, pagination, notification action persistence/dry-run behavior, context-link scoping, and HTTP login/CSRF/content-type/escaping/replay behavior. Tests use disposable fixtures and no external notification service. Interactive browser behavior still needs manual review.
