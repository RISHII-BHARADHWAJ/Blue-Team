# Case assignment and inbox handoff

Use **Case assignment** inside an incident to choose an eligible analyst. The existing assignment capability and target-user eligibility checks still apply. A successful owner change now saves these together:

- The assigned user and case update timestamp.
- A timeline entry recording the previous and new owner.
- An assignment audit entry with both user IDs.
- One `INCIDENT_ASSIGNED` in-app notification to the new owner, linked to the case.

The recipient can open **My inbox** to inspect the notification and follow its case link. Simulated-case messages explicitly say `SIMULATED` and also receive the inbox's simulation label. Messages pass through the existing redactor and include the case number rather than copying evidence or case descriptions. No email, external messaging, playbook or containment action is triggered.

Assigning the current owner again succeeds without changing the case timestamp or creating another timeline, audit or notification row. An older request that proposes the already-current owner is also a harmless retry. Reassigning from A to B creates one new notification for B; A's prior inbox message remains historical and does not imply current ownership. Open the case to see its current owner.

If notification or required assignment-audit persistence fails, the owner change and timeline entry roll back as well. Calls inside an existing transaction use a savepoint and preserve the caller's transaction. No migration is added; this relies on the existing notifications schema through migration 005.

## Preventing stale-page overwrites

The incident page sends the owner it displayed as `expected_assigned_to` when posting the `assign` action to `/api/v1/incidents_detail.php`:

- A positive user ID means “change this only if that user still owns it.”
- JSON `null` (or an empty form field) means “change this only if it is still unassigned.”
- If the current owner differs from that expectation and the requested target, the API responds HTTP 409 with `assignment_conflict`. Reload the case and review the current owner before trying again.
- Invalid expectations return HTTP 422.
- Omitting the expectation retains the older API behavior. Existing three-argument `IncidentManager::assignIncident` calls remain valid.

The guard compares the current owner, not every case field or an assignment revision counter. It does not detect an intervening A → B → A sequence. Concurrent requests use the locked incident row: same-target retries create one message, while competing targets with the same stale expectation yield one successful change and one conflict. Existing permissions and treatment of case lifecycle states are unchanged.

CI covers atomic handoff and rollback, no-op retries, competing assignments, older transaction snapshots, simulation labels, recipient isolation through the personal inbox, HTTP permissions/CSRF, conflict responses and compatibility. Interactive browser behavior has not been tested.
