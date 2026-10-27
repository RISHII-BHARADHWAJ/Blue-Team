# ThreatPulse v1 lab release acceptance

Feature scope is frozen. Remaining changes are limited to failed acceptance checks, installation blockers and release documentation. Production hosting, live endpoint containment, independently managed sensor identities, and retention/archival remain outside this lab release.

## Release gates

| Gate | Evidence required | Current status |
| --- | --- | --- |
| Frozen candidate | Record the final main commit for release | Features through PR #49 merged; theme merge commit `7483c4912135c5e5cf4d2eef93da41289613b803`; documentation update follows |
| Automated regression | Four CI jobs green for the candidate | PR #49 head passed PHP, Compose/HTTP, SOAR and browser jobs; [run 40454230450](https://github.com/RISHII-BHARADHWAJ/Blue-Team/actions/runs/40454230450). Recheck final main candidate before tagging |
| Existing installation | Healthy Compose services, schema through 013 | User reported 53 passed / 0 failed after upgrade. Later Git-clone startup failed with `/start.sh: not found`; Windows line-ending repair supplied, successful restart not yet confirmed |
| Observed-event investigation | Authorized telemetry → evidence → finding/case → owner → note → resolution → report | Component/integration CI passed; local genuine-telemetry walkthrough not recorded |
| Simulated SOAR | Labeled demo → findings/evidence → saved DRY_RUN; real cases separate | Automated demo coverage passed; browser stream creates two batches, stops, and opens an investigation. Local end-to-end preview sign-off not recorded |
| Browser acceptance | Navigation, forms, themes, responsive layout, printable report | Automated desktop/mobile acceptance covers 22 authenticated routes, login, intake, stream and theme preferences. Selected screenshots and printable output reviewed. Actual deployment/role walkthrough remains to be confirmed |
| Release | No unresolved local blockers; known limits recorded; maintainer-approved tag | Feature scope complete for the local demo. No v1.0 tag or deployment sign-off claimed |

Do not mark a gate passed without recording the tested commit, date, result and relevant case/event/run IDs. Green CI is not evidence that the user's existing database was upgraded. Do not run the fixture-heavy CI scripts on that database: they are intended for disposable Compose environments.

## First local checkpoint

From the project directory, after updating code and applying the documented missing migrations (back up the database first):

```powershell
docker compose -p blue-team-main ps
docker compose -p blue-team-main exec -T web php database/verify_schema.php
```

Capture service status and the verifier summary/failures. Do not paste passwords, tokens or raw event payloads. For migration 013 see [manual intake upgrade](manual-case-intake.md#upgrade-existing-installations). Never delete the database volume to force migration. The verifier is read-only and checks listed schema structures; it does not prove data preservation or complete runtime behavior.

## Local walkthroughs

1. Sign in with an analyst account. Verify SOC overview, event evidence, incident queue and inbox load without errors. Check a read-only account cannot perform privileged case changes.
2. Use a genuine authorized sensor event already preserved in the installation. Verify source/submitter, original payload and timestamp, detection finding and linked case. If no suitable telemetry is available, leave this gate pending rather than relabeling synthetic data as observed.
3. Open the case, assign an eligible owner, verify their inbox notification, add a finding note and locate it through note search. Progress the investigation through permitted states and verify timeline entries. Use a designated acceptance case; do not close an ongoing investigation merely to pass a test.
4. Open the report, verify evidence and note references, inspect the printable layout and download the JSON report. Confirm it corresponds to the case shown.
5. Create a separate labeled simulated walkthrough in `demo.php`. Inspect its finding/evidence, run its saved preview, and verify DRY_RUN results. Confirm no real approval or containment was performed and the default real-case queue excludes it.
6. Verify empty-search results, pagination, required-field feedback, and denied-role behavior. Re-submit a completed manual intake form and confirm it returns the same case. Check lead/admin audit history for the recorded actions.

Record failures with the page, account role, steps, expected/actual result and sanitized error. Fix blockers and repeat only the affected checks plus CI. No new features are needed to complete these gates. Also verify the theme switch survives reload and the continuous demo stream stops when requested.

## Finish line

After all gates pass, prepare the v1.0 release notes with the tested commit, setup instructions, demonstration path and explicit lab limitations. Tag/publish only after maintainer approval. Until then the project remains a release candidate, not a completed or production-certified deployment.
