# ThreatPulse workspace design

The interface uses one shared identity across the login, overview, evidence, cases,
intelligence, approvals, reports, and investigation terminal. An ink navigation
rail, warm off-white canvas, restrained green controls, and coral accents replace
the former neon dashboard styling. System fonts keep the interface usable without
an external font service.

`includes/ui/shell.php` owns navigation and the account header;
`assets/css/design-system.css` owns application surfaces and responsive rules;
`assets/js/workspace-shell.js` owns the mobile drawer and table scroll wrappers.
Login has its own matching stylesheet. Page-specific forms and API contracts are
preserved. The initial login destination is the operations overview.

## Verification

The `visual-acceptance` CI job starts a disposable Compose database, creates
explicitly synthetic presentation fixtures, and visits 22 authenticated routes
at desktop (1440 px) and mobile (390 px) widths. It checks page responses, active
navigation, horizontal overflow, mobile navigation, case intake submission, and
report PDF generation. Login is captured at both widths. PNGs, the PDF, and
`results.json` are published as the `visual-acceptance` workflow artifact.

These browser checks complement PHP syntax, database/HTTP smoke checks, and SOAR
regressions. They do not replace checking an actual deployment with its configured
roles, data volumes, and external services. The atlas still depends on external
Leaflet assets and map tiles; evidence and case workflows do not depend on those
services. No database migration is introduced by this redesign.

## Light and dark mode

The header and login page provide an accessible theme switch. The first visit
follows the system color scheme; an explicit choice is saved in browser local
storage and shared across tabs on the same origin. If storage is unavailable,
the switch still works for the current page. Theme initialization runs in the
head before paint. Print uses the light layout regardless of screen theme.

`assets/js/theme.js` owns preference handling; `assets/css/themes.css` owns theme
overrides. Browser acceptance checks persistence, system dark preference, switching
back to light, and every authenticated route in dark mode at both tested widths.
