# Searchable approval queue

The approval control plane at `control_plane/index.php` now searches the full stored queue through the read-only `GET /api/v1/approval_queue.php` endpoint. Previously the page loaded at most 100 requests, searched only those rows, and calculated its counters from that subset.

## Filters and ordering

- Search matches case number/title and action name/full description using the database collation. `%`, `_`, and `!` are literal characters. Input must be valid UTF-8 and at most 200 bytes.
- Status defaults to `PENDING`; an empty status includes all states. Priority filters use the case's current P1–P4 value.
- Real cases are shown by default. Simulated and all-case views are explicit choices, and simulated rows carry a label.
- Newest/oldest ordering uses request time and ID. Priority ordering uses P1 first, then oldest request and ID. Expiry ordering uses earliest deadline and ID, including completed requests when selected.
- Each page contains at most 25 requests. Large positive page numbers clamp to the last page. Filter changes reset to page one. The client cancels superseded requests and ignores late responses.

Counts cover **all matching rows under every selected filter**, rather than just the visible page or the entire unfiltered queue. Critical means matching pending P1/P2 requests. Expiring means matching pending requests whose deadline is strictly less than four hours away. Counts, rows and pagination use one repeatable-read snapshot and one database-server timestamp. The snapshot is closed before returning when the service owns it; caller transactions remain caller-owned. Separate page requests may shift as requests are added or changed.

## Expiration and review

At or after its expiry time, a stored `PENDING` row is presented and filtered as `EXPIRED`. The response also includes `stored_status`. Reading this endpoint does not update approval state, record a decision, create an audit event, or execute a playbook. Completed/cancelled decisions retain their recorded status regardless of deadline. Queue expiry countdowns use server-computed seconds; they refresh with polling rather than the browser's local timezone.

Review and decision dialogs continue using the existing detail and decision endpoints. Those endpoints remain authoritative and can reject a request that has changed or expired since the queue was loaded. The older `approvals.php` list API and its maintenance behavior remain compatible; only this new queue endpoint guarantees read-only browsing. Opening a detail continues the existing detail audit behavior.

## Access and displayed data

The endpoint requires authentication and `view_incidents`, matching existing approval read access. It accepts GET only and sends `Cache-Control: no-store`. Queue access does not grant approval permission. The response selects summary metadata only, omits action payloads and decision reasons, limits description previews to 300 characters, and applies the existing pattern-based secret redactor to titles/action text. This redactor is not a guarantee that arbitrary metadata contains no secrets.

Failed requests show an unavailable state and clear rows/counters rather than presenting old counts as current. No database migration is required.

## Verification

CI includes a 106-request fixture spanning pages, full-text description search beyond the preview, literal wildcard search, priority/expiry ordering, simulation separation, expired display without writes, invalid inputs, transaction handling, and HTTP authentication/method/error behavior. A Node test exercises the actual control-plane script with a minimal DOM and deferred network responses, including late-response rejection, safe text rendering and modal data. This is not an interactive browser layout test.
