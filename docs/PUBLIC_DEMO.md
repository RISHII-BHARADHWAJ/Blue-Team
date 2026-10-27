# Free public demo on Render

This deployment uses one Free Docker web service, its built-in HTTPS address, and a disposable embedded MariaDB instance. No paid database, disk or custom domain is provisioned. Free-plan usage limits and any account-level billing settings still apply; review them in Render.

**Saved data can disappear whenever Render replaces/restarts the container.** The service may sleep when idle. Keep real investigations and valuable data in your existing local Docker installation. This deployment never connects to that local database.

The Blueprint creates private random `DB_PASS` and `PUBLIC_DEMO_ADMIN_PASSWORD` values. Sign in as `admin`, using the latter value from the service's Environment settings. Do not publish it in the repository or share it in a public demo link. All other shipped account passwords are randomized before HTTP starts; documented local passwords do not work here.

Startup applies the SIEM bootstrap and all SOAR migrations, verifies the schema, creates one explicitly labeled training case, and starts Apache with bounded workers. The Training lab can generate simulated alert batches while you demonstrate the app. Scheduled feed collection is disabled to avoid background traffic and contention on a small free instance. Auto-deploy is disabled to avoid unnecessary resets.

The runtime database account has data read/write privileges but cannot change table definitions. MariaDB only listens on a local Unix socket. The HTTP worker cannot write application source. Sessions use Secure cookies behind Render HTTPS. `/health.php` provides a minimal readiness check without consuming the login rate limit.

To deploy, connect this repository to a Render Blueprint, select the verified deployment branch (or merge it into main first), and confirm the service plan is Free. Never add a persistent disk or paid database when using the free-only setup. Check build/start logs and `/health.php`, then sign in and run a Training lab batch. The service is only considered deployed after these live checks pass.

The `Free public demo startup` CI job boots the image with a 512 MiB memory limit, checks schema/account/privilege protections, and verifies repeated initialization. This is a small demonstration service, not a high-availability production deployment. See SECURITY_REVIEW.md for the wider security scope and remaining limitations.
