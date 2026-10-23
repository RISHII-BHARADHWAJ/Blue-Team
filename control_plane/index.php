<?php
/**
 * ThreatPulse SOAR - SOC Approval & Response Control Plane
 *
 * Professional, high-fidelity analyst control plane for inspecting incident evidence,
 * reviewing Phase 5 explainable risk scores, evaluating requested SOAR response actions,
 * executing atomic approvals/rejections, and monitoring playbook execution timelines.
 */

session_name('CYBERTECH_SECURE_SESSION');
@session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict', 'use_strict_mode' => true]);

if (empty($_SESSION['analyst']) && empty($_SESSION['username']) && empty($_SESSION['user_id'])) {
    header('Location: ../login.php');
    exit;
}

header('Cache-Control: no-store');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header_remove('X-Powered-By');

require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/soar/SoarAuth.php';

$auth = SoarAuth::getContext($pdo);
$csrfToken = generateCSRFToken();
$userTier = $auth['tier'] ?? SoarAuth::TIER_1;
$canApprove = SoarAuth::hasPermission($userTier, 'approve_actions');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatPulse SOAR | Approval Control Plane</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Rajdhani:wght@500;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #020B18;
            --bg-panel: #050F1F;
            --bg-card: #08162B;
            --border-blue: rgba(13, 110, 253, 0.25);
            --border-highlight: rgba(0, 180, 216, 0.4);
            --text-primary: #E0EEFF;
            --text-secondary: #7BA3CC;
            --text-muted: #4A6E94;
            --neon-cyan: #00B4D8;
            --neon-teal: #17D4BE;
            --neon-green: #00FF9C;
            --neon-red: #FF3B3B;
            --neon-amber: #FFB703;
            --neon-blue: #0D6EFD;
            --font-heading: 'Rajdhani', sans-serif;
            --font-mono: 'Share Tech Mono', monospace;
            --font-body: 'IBM Plex Sans', sans-serif;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: var(--bg-dark);
            color: var(--text-primary);
            font-family: var(--font-body);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Header */
        .header {
            background: var(--bg-panel);
            border-bottom: 1px solid var(--border-blue);
            padding: 12px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .brand-group {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .brand-title {
            font-family: var(--font-heading);
            font-size: 1.4rem;
            font-weight: 700;
            letter-spacing: 2px;
            color: #fff;
            text-decoration: none;
        }
        .soar-badge {
            background: rgba(0, 180, 216, 0.15);
            border: 1px solid var(--neon-cyan);
            color: var(--neon-cyan);
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 1px;
            padding: 2px 8px;
            border-radius: 3px;
            font-family: var(--font-mono);
        }
        .status-dot {
            width: 8px; height: 8px; border-radius: 50%;
            background: var(--neon-green);
            box-shadow: 0 0 8px var(--neon-green);
            display: inline-block;
            margin-right: 6px;
        }
        .poll-status {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: var(--neon-teal);
            display: flex;
            align-items: center;
        }

        .nav-links {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .nav-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 600;
            padding: 6px 12px;
            border-radius: 4px;
            transition: all 0.2s;
        }
        .nav-link:hover, .nav-link.active {
            color: #fff;
            background: rgba(13, 110, 253, 0.15);
            border: 1px solid var(--border-blue);
        }

        .user-actions {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .tier-tag {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 4px;
            letter-spacing: 1px;
        }
        .tier-ADMIN { background: rgba(255, 59, 59, 0.2); border: 1px solid var(--neon-red); color: var(--neon-red); }
        .tier-LEAD  { background: rgba(255, 183, 3, 0.2); border: 1px solid var(--neon-amber); color: var(--neon-amber); }
        .tier-TIER2 { background: rgba(0, 180, 216, 0.2); border: 1px solid var(--neon-cyan); color: var(--neon-cyan); }
        .tier-TIER1 { background: rgba(123, 163, 204, 0.2); border: 1px solid var(--text-secondary); color: var(--text-secondary); }

        .btn-bell {
            background: transparent;
            border: 1px solid var(--border-blue);
            color: var(--neon-cyan);
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            position: relative;
            font-size: 0.9rem;
        }
        .bell-badge {
            position: absolute;
            top: -6px; right: -6px;
            background: var(--neon-red);
            color: #fff;
            font-size: 0.65rem;
            font-weight: 700;
            padding: 1px 5px;
            border-radius: 8px;
        }

        /* Metrics */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            padding: 20px 24px;
        }
        .m-card {
            background: var(--bg-card);
            border: 1px solid var(--border-blue);
            border-radius: 6px;
            padding: 16px 20px;
            position: relative;
            overflow: hidden;
        }
        .m-card::before {
            content: '';
            position: absolute;
            left: 0; top: 0; bottom: 0; width: 4px;
            background: var(--neon-cyan);
        }
        .m-card.p1::before { background: var(--neon-red); }
        .m-card.warn::before { background: var(--neon-amber); }
        .m-card.green::before { background: var(--neon-green); }
        .m-label {
            font-size: 0.7rem;
            color: var(--text-secondary);
            letter-spacing: 1.5px;
            text-transform: uppercase;
            font-weight: 600;
        }
        .m-value {
            font-family: var(--font-heading);
            font-size: 2.2rem;
            font-weight: 700;
            margin-top: 4px;
        }

        /* Main Area */
        .container {
            padding: 0 24px 30px;
            flex: 1;
        }
        .control-bar {
            background: var(--bg-panel);
            border: 1px solid var(--border-blue);
            border-radius: 6px;
            padding: 12px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            gap: 14px;
        }
        .filter-controls {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-select, .filter-input {
            background: #010712;
            border: 1px solid var(--border-blue);
            color: var(--text-primary);
            padding: 7px 12px;
            font-size: 0.85rem;
            border-radius: 4px;
            font-family: var(--font-body);
            outline: none;
        }
        .filter-select:focus, .filter-input:focus {
            border-color: var(--neon-cyan);
        }

        /* Table */
        .table-card {
            background: var(--bg-panel);
            border: 1px solid var(--border-blue);
            border-radius: 6px;
            overflow: hidden;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            text-align: left;
        }
        .data-table th {
            background: #030A14;
            padding: 12px 16px;
            color: var(--text-secondary);
            font-size: 0.75rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            border-bottom: 1px solid var(--border-blue);
        }
        .data-table td {
            padding: 14px 16px;
            border-bottom: 1px solid rgba(13, 110, 253, 0.1);
            vertical-align: middle;
        }
        .data-table tr:hover {
            background: rgba(13, 110, 253, 0.06);
        }
        .data-table tr.p1-highlight {
            background: rgba(255, 59, 59, 0.04);
            border-left: 3px solid var(--neon-red);
        }

        /* Badges */
        .badge {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 3px;
            display: inline-block;
        }
        .badge-P1 { background: rgba(255, 59, 59, 0.25); color: #FF7B7B; border: 1px solid var(--neon-red); }
        .badge-P2 { background: rgba(255, 183, 3, 0.25); color: #FFC038; border: 1px solid var(--neon-amber); }
        .badge-P3 { background: rgba(0, 180, 216, 0.25); color: #48CAE4; border: 1px solid var(--neon-cyan); }
        .badge-P4 { background: rgba(123, 163, 204, 0.2); color: #90B6DE; border: 1px solid var(--text-secondary); }

        .badge-PENDING   { background: rgba(255, 183, 3, 0.2); color: var(--neon-amber); border: 1px solid var(--neon-amber); }
        .badge-APPROVED  { background: rgba(0, 255, 156, 0.2); color: var(--neon-green); border: 1px solid var(--neon-green); }
        .badge-REJECTED  { background: rgba(255, 59, 59, 0.2); color: var(--neon-red); border: 1px solid var(--neon-red); }
        .badge-EXPIRED   { background: rgba(123, 163, 204, 0.2); color: var(--text-secondary); border: 1px solid var(--text-secondary); }
        .badge-CANCELLED { background: rgba(74, 110, 148, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }

        /* Buttons */
        .btn {
            background: rgba(13, 110, 253, 0.2);
            border: 1px solid var(--neon-blue);
            color: #fff;
            padding: 6px 14px;
            font-size: 0.8rem;
            font-weight: 600;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn:hover {
            background: rgba(13, 110, 253, 0.4);
            box-shadow: 0 0 10px rgba(13, 110, 253, 0.3);
        }
        .btn-approve {
            background: rgba(0, 255, 156, 0.15);
            border-color: var(--neon-green);
            color: var(--neon-green);
        }
        .btn-approve:hover {
            background: rgba(0, 255, 156, 0.3);
            box-shadow: 0 0 10px rgba(0, 255, 156, 0.3);
        }
        .btn-reject {
            background: rgba(255, 59, 59, 0.15);
            border-color: var(--neon-red);
            color: var(--neon-red);
        }
        .btn-reject:hover {
            background: rgba(255, 59, 59, 0.3);
            box-shadow: 0 0 10px rgba(255, 59, 59, 0.3);
        }

        /* Modals */
        .modal-mask {
            position: fixed;
            top: 0; left: 0; width: 100vw; height: 100vh;
            background: rgba(2, 11, 24, 0.85);
            backdrop-filter: blur(4px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        .modal-mask.open { display: flex; }
        .modal-panel {
            background: var(--bg-panel);
            border: 1px solid var(--border-highlight);
            border-radius: 8px;
            max-width: 960px;
            width: 90%;
            max-height: 88vh;
            display: flex;
            flex-direction: column;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.9);
            animation: fadeIn 0.18s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.97); }
            to { opacity: 1; transform: scale(1); }
        }
        .modal-head {
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-blue);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-title {
            font-family: var(--font-heading);
            font-size: 1.3rem;
            font-weight: 700;
            color: #fff;
            letter-spacing: 1px;
        }
        .modal-close {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            line-height: 1;
        }
        .modal-body {
            padding: 20px 24px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }
        .modal-foot {
            padding: 14px 24px;
            border-top: 1px solid var(--border-blue);
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }

        /* Detail Layout */
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        .pane {
            background: #020814;
            border: 1px solid var(--border-blue);
            border-radius: 6px;
            padding: 14px;
        }
        .pane-heading {
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: var(--neon-cyan);
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
        }
        .code-block {
            background: #01040A;
            border: 1px solid var(--border-blue);
            border-radius: 4px;
            padding: 10px;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: var(--neon-green);
            max-height: 160px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Notifications Popup */
        .notif-popup {
            position: absolute;
            top: 55px; right: 24px;
            width: 380px;
            background: var(--bg-panel);
            border: 1px solid var(--border-highlight);
            border-radius: 6px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.9);
            display: none;
            flex-direction: column;
            max-height: 420px;
            z-index: 200;
        }
        .notif-popup.open { display: flex; }
        .notif-row {
            padding: 12px 16px;
            border-bottom: 1px solid rgba(13, 110, 253, 0.1);
            cursor: pointer;
            transition: background 0.15s;
        }
        .notif-row:hover { background: rgba(0, 180, 216, 0.05); }
        .notif-row.unread { border-left: 3px solid var(--neon-cyan); }
    </style>
</head>
<body>

    <!-- Header -->
    <header class="header">
        <div class="brand-group">
            <a href="index.php" class="brand-title">ThreatPulse</a>
            <span class="soar-badge">SOAR CONTROL PLANE</span>
            <div class="poll-status">
                <span class="status-dot"></span>
                <span id="pollStatusText">LIVE MONITORING</span>
            </div>
        </div>

        <nav class="nav-links">
            <a href="../dashboard.php" class="nav-link">SIEM Dashboard</a>
            <a href="../terminal.php" class="nav-link">IR Terminal</a>
            <a href="index.php" class="nav-link active">Approval Queue</a>
        </nav>

        <div class="user-actions">
            <button class="btn-bell" id="bellBtn" title="In-App Notifications">
                🔔 <span class="bell-badge" id="notifBadge" style="display:none;">0</span>
            </button>
            <span class="tier-tag tier-<?= htmlspecialchars($userTier) ?>">TIER: <?= htmlspecialchars($userTier) ?></span>
            <span style="font-size:0.85rem; color:var(--text-secondary); font-family:var(--font-mono);">
                <?= htmlspecialchars($auth['actor']) ?>
            </span>
            <a href="../logout.php" class="btn btn-reject" style="padding:4px 10px; font-size:0.75rem;">SIGN OUT</a>
        </div>
    </header>

    <!-- Notification Dropdown -->
    <div class="notif-popup" id="notifPopup">
        <div style="padding:10px 16px; border-bottom:1px solid var(--border-blue); display:flex; justify-content:space-between; align-items:center;">
            <strong style="font-size:0.8rem; color:var(--neon-cyan); letter-spacing:1px;">NOTIFICATIONS</strong>
            <a href="../notifications.php" class="btn" style="padding:2px 8px; font-size:0.7rem;">Open inbox</a>
        </div>
        <div id="notifFeedback" role="status" aria-live="polite"></div>
        <div id="notifList" style="overflow-y:auto; flex:1;">
            <div style="padding:16px; text-align:center; color:var(--text-muted); font-size:0.8rem;">No notifications.</div>
        </div>
    </div>

    <!-- Metrics Row -->
    <section class="metrics-grid">
        <div class="m-card warn">
            <div class="m-label">MATCHING PENDING APPROVALS</div>
            <div class="m-value" style="color:var(--neon-amber);" id="metricPending">0</div>
        </div>
        <div class="m-card p1">
            <div class="m-label">MATCHING P1 / P2 PENDING</div>
            <div class="m-value" style="color:var(--neon-red);" id="metricCritical">0</div>
        </div>
        <div class="m-card warn">
            <div class="m-label">MATCHING EXPIRING IN &lt; 4 HOURS</div>
            <div class="m-value" style="color:var(--neon-amber);" id="metricExpiring">0</div>
        </div>
        <div class="m-card green">
            <div class="m-label">ACTIVE MONITOR INTERVAL</div>
            <div class="m-value" style="color:var(--neon-green);" id="metricInterval">8s</div>
        </div>
    </section>

    <!-- Main Queue Container -->
    <main class="container">
        <div class="control-bar">
            <div class="filter-controls">
                <select aria-label="Approval status" id="statusFilter" class="filter-select">
                    <option value="">Status: ALL</option>
                    <option value="PENDING" selected>Status: PENDING</option>
                    <option value="APPROVED">Status: APPROVED</option>
                    <option value="REJECTED">Status: REJECTED</option>
                    <option value="EXPIRED">Status: EXPIRED</option>
                    <option value="CANCELLED">Status: CANCELLED</option>
                </select>

                <select aria-label="Case priority" id="priorityFilter" class="filter-select">
                    <option value="">Priority: ALL</option>
                    <option value="P1">Priority: P1 (Critical)</option>
                    <option value="P2">Priority: P2 (High)</option>
                    <option value="P3">Priority: P3 (Medium)</option>
                    <option value="P4">Priority: P4 (Low)</option>
                </select>

                <select id="kindFilter" class="filter-select" aria-label="Case provenance"><option value="observed">Real cases</option><option value="simulated">Simulated cases</option><option value="all">All cases</option></select>
                <select id="sortFilter" class="filter-select" aria-label="Queue order"><option value="newest">Newest requests</option><option value="oldest">Oldest requests</option><option value="priority">Priority, oldest first</option><option value="expiry">Earliest expiry</option></select>
                <input type="search" id="searchInput" class="filter-input" aria-label="Search actions or cases" placeholder="Search actions or cases..." maxlength="200" style="width:240px;">
            </div>

            <div>
                <button class="btn" id="refreshBtn">⟳ Refresh</button>
            </div>
        </div>

        <p id="queueSummary" role="status" aria-live="polite" style="margin:12px 0;">Loading queue…</p>
        <p style="color:var(--text-secondary);margin:12px 0;">Counts cover all matching requests. Expiration uses database server time; browsing this queue never decides a request. Simulation is labeled separately.</p>
        <div class="table-card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Incident</th>
                        <th>Priority &amp; Risk</th>
                        <th>Action Requested</th>
                        <th>Required Tier</th>
                        <th>Requested At</th>
                        <th>Expires</th>
                        <th>Status</th>
                        <th style="text-align:right;">Control Actions</th>
                    </tr>
                </thead>
                <tbody id="queueTbody">
                    <tr>
                        <td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">
                            Loading approval queue...
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
        <nav aria-label="Approval pages" style="display:flex;gap:16px;align-items:center;margin:16px 0;">
            <button class="btn" id="queuePrevious" disabled>Previous</button><span id="queuePage">Page —</span><button class="btn" id="queueNext" disabled>Next</button>
        </nav>
    </main>

    <!-- Approval Detail Modal -->
    <div class="modal-mask" id="detailModal">
        <div class="modal-panel">
            <div class="modal-head">
                <div class="modal-title" id="detailModalTitle">Approval Request Inspection</div>
                <button class="modal-close" onclick="closeModal('detailModal')">&times;</button>
            </div>
            <div class="modal-body" id="detailModalBody">
                <!-- Injected dynamically via JS -->
            </div>
            <div class="modal-foot" id="detailModalFoot">
                <!-- Injected dynamically based on permissions & state -->
            </div>
        </div>
    </div>

    <!-- Confirm Approve Modal -->
    <div class="modal-mask" id="confirmModal">
        <div class="modal-panel" style="max-width:540px;">
            <div class="modal-head">
                <div class="modal-title" style="color:var(--neon-green);">Confirm Response Action Execution</div>
                <button class="modal-close" onclick="closeModal('confirmModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div style="font-size:0.9rem; line-height:1.5;">
                    You are about to authorize and execute the following privileged SOAR action:
                </div>
                <div class="pane" style="margin-top:10px;">
                    <div><strong>Action:</strong> <span id="confirmActionName" style="color:var(--neon-cyan);"></span></div>
                    <div style="margin-top:6px;"><strong>Incident:</strong> <span id="confirmIncidentNum"></span></div>
                    <div style="margin-top:6px;"><strong>Run ID:</strong> <span id="confirmRunId"></span></div>
                </div>
                <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:10px;">
                    This decision will be immutably recorded in the security audit log and the incident timeline. Execution will immediately resume at the current step.
                </div>
            </div>
            <div class="modal-foot">
                <button class="btn" onclick="closeModal('confirmModal')">Cancel</button>
                <button class="btn btn-approve" id="executeApproveBtn">Authorize &amp; Resume Playbook</button>
            </div>
        </div>
    </div>

    <!-- Rejection Reason Modal -->
    <div class="modal-mask" id="rejectModal">
        <div class="modal-panel" style="max-width:540px;">
            <div class="modal-head">
                <div class="modal-title" style="color:var(--neon-red);">Reject SOAR Response Action</div>
                <button class="modal-close" onclick="closeModal('rejectModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div style="font-size:0.9rem;">
                    Rejecting this action will cancel or fail the playbook run. An explanatory reason is mandatory:
                </div>
                <textarea id="rejectReasonInput" class="filter-input" rows="4" style="width:100%; margin-top:12px; resize:vertical;" placeholder="Provide a detailed reason for rejecting this action (min 10 chars)..."></textarea>
                <div style="display:flex; justify-content:space-between; font-size:0.75rem; color:var(--text-muted); margin-top:4px;">
                    <span>Minimum 10 characters</span>
                    <span id="charCount">0 / 1000</span>
                </div>
            </div>
            <div class="modal-foot">
                <button class="btn" onclick="closeModal('rejectModal')">Cancel</button>
                <button class="btn btn-reject" id="executeRejectBtn">Confirm Rejection</button>
            </div>
        </div>
    </div>

    <!-- Playbook Run Monitor Modal -->
    <div class="modal-mask" id="runMonitorModal">
        <div class="modal-panel" style="max-width:800px;">
            <div class="modal-head">
                <div class="modal-title" id="runMonitorTitle">Playbook Execution Monitor</div>
                <button class="modal-close" onclick="closeModal('runMonitorModal')">&times;</button>
            </div>
            <div class="modal-body" id="runMonitorBody">
                <!-- Injected dynamically -->
            </div>
            <div class="modal-foot">
                <button class="btn" onclick="closeModal('runMonitorModal')">Close</button>
            </div>
        </div>
    </div>

    <!-- Embedded CSRF and Session Identity -->
    <input type="hidden" id="csrfToken" value="<?= htmlspecialchars($csrfToken) ?>">
    <input type="hidden" id="userTier" value="<?= htmlspecialchars($userTier) ?>">
    <input type="hidden" id="canApprovePerm" value="<?= $canApprove ? '1' : '0' ?>">

    <script>
        // State
        const CSRF_TOKEN = document.getElementById('csrfToken').value;
        const USER_TIER  = document.getElementById('userTier').value;
        const CAN_APPROVE = document.getElementById('canApprovePerm').value === '1';

        let approvalsData = [];
        let queuePage = 1;
        let queuePages = 1;
        let queueRequest = 0;
        let queueController = null;
        let searchTimer = null;
        let activeApprovalId = null;
        let pollTimer = null;
        let isPolling = true;

        const tierRanks = { 'TIER1': 1, 'TIER2': 2, 'LEAD': 3, 'ADMIN': 4 };

        function meetsTier(actual, required) {
            return (tierRanks[actual] || 0) >= (tierRanks[required] || 0);
        }

        // Search and counts apply to the full matching queue, not just the visible page.
        async function fetchQueue() {
            const request = ++queueRequest;
            if (queueController) queueController.abort();
            queueController = new AbortController();
            const params = new URLSearchParams({
                status: document.getElementById('statusFilter').value,
                priority: document.getElementById('priorityFilter').value,
                kind: document.getElementById('kindFilter').value,
                sort: document.getElementById('sortFilter').value,
                q: document.getElementById('searchInput').value,
                page: String(queuePage)
            });
            document.getElementById('queueSummary').textContent = 'Loading matching requests…';
            document.getElementById('queuePrevious').disabled = true;
            document.getElementById('queueNext').disabled = true;
            try {
                const res = await fetch('../api/v1/approval_queue.php?' + params, {signal: queueController.signal});
                const json = await res.json();
                if (!res.ok || !json.success) throw new Error(json.message || 'Queue request failed.');
                if (request !== queueRequest) return;
                approvalsData = json.data;
                queuePage = json.pagination.page;
                queuePages = json.pagination.pages;
                renderQueue();
                updateMetrics(json.metrics);
                document.getElementById('queueSummary').textContent = `${json.pagination.total} matching requests · ${approvalsData.length} shown · as of ${json.as_of} (server time)`;
                document.getElementById('queuePage').textContent = `Page ${queuePage} of ${queuePages}`;
                document.getElementById('queuePrevious').disabled = queuePage <= 1;
                document.getElementById('queueNext').disabled = queuePage >= queuePages;
            } catch (err) {
                if (request !== queueRequest || err.name === 'AbortError') return;
                approvalsData = [];
                document.getElementById('queueTbody').innerHTML = '<tr><td colspan="8" style="padding:30px;">Approval queue unavailable. Refresh to retry.</td></tr>';
                document.getElementById('queueSummary').textContent = err.message;
                document.getElementById('queuePage').textContent = 'Page unavailable';
                updateMetrics({pending:'—',critical:'—',expiring:'—'});
            }
        }

        // Fetch Notifications
        async function fetchNotifications() {
            try {
                const res = await fetch('../api/v1/notifications.php?unread_only=1&limit=10');
                if (!res.ok) return;
                const json = await res.json();
                if (json.success) {
                    const badge = document.getElementById('notifBadge');
                    if (json.unread_count > 0) {
                        badge.textContent = json.unread_count;
                        badge.style.display = 'inline-block';
                    } else {
                        badge.style.display = 'none';
                    }
                    renderNotifications(json.data || []);
                }
            } catch (e) {}
        }

        function renderNotifications(items) {
            const list = document.getElementById('notifList');
            if (!items.length) {
                list.innerHTML = '<div style="padding:16px; text-align:center; color:var(--text-muted); font-size:0.8rem;">No unread notifications.</div>';
                return;
            }
            list.innerHTML = items.map(n => `
                <div class="notif-row unread" onclick="handleNotifClick(${n.id}, ${n.approval_id})">
                    <div style="font-size:0.8rem; font-weight:700; color:#fff;">${escapeHtml(n.title)}</div>
                    <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:2px;">${escapeHtml(n.message)}</div>
                    <div style="font-size:0.7rem; color:var(--text-muted); margin-top:4px; font-family:var(--font-mono);">${escapeHtml(n.created_at)}</div>
                </div>
            `).join('');
        }

        async function handleNotifClick(notifId, approvalId) {
            const feedback = document.getElementById('notifFeedback');
            feedback.textContent = '';
            try {
                const response = await fetch('../api/v1/notifications.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                    body: JSON.stringify({ notification_id: notifId })
                });
                const result = await response.json();
                if (!response.ok || !result.success) throw new Error('acknowledgement_failed');
                await fetchNotifications();
                document.getElementById('notifPopup').classList.remove('open');
                if (approvalId) openDetail(approvalId);
            } catch (_) {
                feedback.textContent = 'Could not confirm the read status. Open your inbox to retry.';
            }
        }

        // Render Queue
        function renderQueue() {
            const tbody = document.getElementById('queueTbody');
            const filtered = approvalsData;

            if (!filtered.length) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">No approvals match filter criteria.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(a => {
                const isP1 = a.incident_priority === 'P1';
                const userCanApproveThis = CAN_APPROVE && meetsTier(USER_TIER, a.required_tier) && a.status === 'PENDING';

                return `
                    <tr class="${isP1 ? 'p1-highlight' : ''}">
                        <td>
                            <strong style="color:#fff;">${escapeHtml(a.incident_number || 'INC-#' + a.incident_id)}</strong>
                            <div style="color:var(--text-secondary); font-size:0.75rem;">${escapeHtml(a.incident_title || '')}</div>${a.is_simulated ? '<strong style="color:var(--neon-amber);">SIMULATED</strong>' : ''}
                        </td>
                        <td>
                            <span class="badge badge-${escapeHtml(a.incident_priority || 'P3')}">${escapeHtml(a.incident_priority || 'P3')}</span>
                            <span style="font-family:var(--font-mono); font-size:0.75rem; margin-left:6px; color:var(--text-secondary);">Score: ${a.incident_risk_score ?? 0}</span>
                        </td>
                        <td>
                            <div style="font-weight:600; color:var(--neon-cyan);">${escapeHtml(a.action_name || 'UNKNOWN')}</div>
                            <div style="color:var(--text-muted); font-size:0.75rem;">${escapeHtml(a.action_description || '')}${a.description_truncated ? '… (preview)' : ''}</div>
                        </td>
                        <td>
                            <span class="tier-tag tier-${escapeHtml(a.required_tier || 'LEAD')}">${escapeHtml(a.required_tier || 'LEAD')}</span>
                        </td>
                        <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-secondary);">
                            ${escapeHtml(a.requested_at || '')}
                        </td>
                        <td style="font-family:var(--font-mono); font-size:0.75rem;">
                            ${formatExpiry(a.expires_at, a.status, a.expires_in_seconds)}
                        </td>
                        <td>
                            <span class="badge badge-${escapeHtml(a.status)}">${escapeHtml(a.status)}</span>
                        </td>
                        <td style="text-align:right;">
                            <button class="btn" onclick="openDetail(${a.id})">Review</button>
                            ${userCanApproveThis ? `
                                <button class="btn btn-approve" onclick="openQueueApprove(${a.id})">Approve</button>
                                <button class="btn btn-reject" onclick="openRejectModal(${a.id})">Reject</button>
                            ` : ''}
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function openQueueApprove(id) {
            const row = approvalsData.find(item => item.id === id);
            if (row) openApproveModal(id, row.action_name, row.incident_number || '', row.playbook_run_id);
        }

        function formatExpiry(expiresAt, status, seconds = null) {
            if (status !== 'PENDING') return '<span style="color:var(--text-muted);">-</span>';
            const diffMs = seconds === null ? new Date(expiresAt) - new Date() : seconds * 1000;
            if (diffMs <= 0) return '<span style="color:var(--neon-red); font-weight:700;">EXPIRED</span>';
            const hours = Math.floor(diffMs / 3600000);
            const mins = Math.floor((diffMs % 3600000) / 60000);
            return `<span style="color:${hours < 2 ? 'var(--neon-red)' : 'var(--neon-amber)'};">${hours}h ${mins}m</span>`;
        }

        function updateMetrics(metrics) {
            document.getElementById('metricPending').textContent = metrics.pending;
            document.getElementById('metricCritical').textContent = metrics.critical;
            document.getElementById('metricExpiring').textContent = metrics.expiring;
        }

        // Open Detail Modal
        async function openDetail(id) {
            activeApprovalId = id;
            const body = document.getElementById('detailModalBody');
            const foot = document.getElementById('detailModalFoot');
            body.innerHTML = '<div style="text-align:center; padding:40px; color:var(--text-secondary);">Loading full approval context and risk breakdown...</div>';
            foot.innerHTML = '';
            openModal('detailModal');

            try {
                const res = await fetch(`../api/v1/approvals_detail.php?id=${id}`);
                if (!res.ok) throw new Error('API returned status ' + res.status);
                const json = await res.json();
                if (!json.success) throw new Error(json.message || 'Failed to load details.');

                const data = json.data;
                const a = data.approval;
                const prev = data.action_preview;
                const risk = data.risk_assessment;
                const evidence = data.evidence;

                document.getElementById('detailModalTitle').textContent = `Approval Request #${a.id} — ${a.action_name}`;

                // Render detail body
                body.innerHTML = `
                    <div class="grid-2">
                        <!-- Incident Context -->
                        <div class="pane">
                            <div class="pane-heading">Incident Overview <span>${escapeHtml(a.incident_number || '')}</span></div>
                            <div style="font-size:1.05rem; font-weight:700; color:#fff;">${escapeHtml(a.incident_title || 'Untitled Incident')}</div>
                            <div style="margin-top:8px; display:flex; gap:8px;">
                                <span class="badge badge-${escapeHtml(a.incident_priority || 'P3')}">${escapeHtml(a.incident_priority || 'P3')}</span>
                                <span class="badge" style="background:#0D1F38; color:var(--neon-cyan);">Severity: ${escapeHtml(a.incident_severity || 'MEDIUM')}</span>
                                <span class="badge" style="background:#0D1F38; color:var(--text-secondary);">${escapeHtml(a.attack_category || 'Unknown')}</span>
                            </div>
                            <div style="margin-top:12px; font-size:0.8rem; color:var(--text-secondary);">
                                <div><strong>MITRE Tactics:</strong> ${escapeHtml(a.mitre_tactics || 'None detected')}</div>
                                <div style="margin-top:4px;"><strong>MITRE Techniques:</strong> ${escapeHtml(a.mitre_techniques || 'None detected')}</div>
                            </div>
                        </div>

                        <!-- Action Preview -->
                        <div class="pane">
                            <div class="pane-heading">Action Preview (Sanitized) <span style="color:var(--neon-green);">${escapeHtml(prev.risk_level)} RISK</span></div>
                            <div style="font-size:0.95rem; font-weight:700; color:var(--neon-cyan);">${escapeHtml(prev.action_type)}</div>
                            <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:2px;">${escapeHtml(prev.description)}</div>
                            <div style="margin-top:8px; font-size:0.75rem; color:var(--text-secondary);">
                                <strong>Required Approval Tier:</strong> <span class="tier-tag tier-${escapeHtml(prev.required_tier)}">${escapeHtml(prev.required_tier)}</span>
                            </div>
                            <div style="margin-top:10px; font-size:0.75rem; font-weight:700; color:var(--text-secondary);">RESOLVED PARAMETERS:</div>
                            <pre class="code-block" style="margin-top:4px;">${escapeHtml(JSON.stringify(prev.resolved_parameters, null, 2))}</pre>
                        </div>
                    </div>

                    <!-- Phase 5 Explainable Risk Breakdown -->
                    <div class="pane">
                        <div class="pane-heading">Phase 5 Explainable Risk Factor Breakdown
                            <span>Total Score: <strong style="color:var(--neon-cyan);">${risk ? risk.risk_score : (a.incident_risk_score || 0)}/100</strong> (${risk ? risk.confidence : 'MEDIUM'} Conf)</span>
                        </div>
                        ${renderRiskTable(risk)}
                    </div>

                    <!-- Correlated Evidence -->
                    <div class="grid-2">
                        <div class="pane">
                            <div class="pane-heading">Correlated Alerts (${evidence.correlated_alerts_count})</div>
                            ${renderAlertsList(evidence.alerts_sample)}
                        </div>

                        <div class="pane">
                            <div class="pane-heading">Correlated IOCs (${evidence.iocs_count})</div>
                            ${renderIocsList(evidence.iocs)}
                        </div>
                    </div>

                    <!-- Lifecycle Metadata -->
                    <div class="pane" style="font-size:0.8rem; color:var(--text-secondary);">
                        <div class="pane-heading">Lifecycle &amp; Audit Status</div>
                        <div class="grid-2">
                            <div>
                                <div><strong>Requested By:</strong> ${escapeHtml(a.analyst_username || 'Automation')}</div>
                                <div style="margin-top:4px;"><strong>Requested At:</strong> ${escapeHtml(a.requested_at)}</div>
                                <div style="margin-top:4px;"><strong>Expires At:</strong> ${escapeHtml(a.expires_at)}</div>
                            </div>
                            <div>
                                <div><strong>Status:</strong> <span class="badge badge-${escapeHtml(a.status)}">${escapeHtml(a.status)}</span></div>
                                ${a.reviewed_by ? `<div style="margin-top:4px;"><strong>Decided By:</strong> ${escapeHtml(a.reviewer_username || 'User #' + a.reviewed_by)}</div>` : ''}
                                ${a.decided_at ? `<div style="margin-top:4px;"><strong>Decided At:</strong> ${escapeHtml(a.decided_at)}</div>` : ''}
                                ${a.rejection_reason ? `<div style="margin-top:4px; color:var(--neon-red);"><strong>Rejection Reason:</strong> ${escapeHtml(a.rejection_reason)}</div>` : ''}
                            </div>
                        </div>
                    </div>
                `;

                // Footer Buttons
                const userCanApprove = CAN_APPROVE && meetsTier(USER_TIER, a.required_tier) && a.status === 'PENDING';
                foot.innerHTML = `
                    <button class="btn" onclick="openRunMonitor(${a.playbook_run_id})">View Playbook Run</button>
                    ${userCanApprove ? `
                        <button class="btn btn-reject" onclick="openRejectModal(${a.id})">Reject Action</button>
                        <button class="btn btn-approve" onclick="openApproveModal(${a.id}, '${escapeHtml(a.action_name)}', '${escapeHtml(a.incident_number || '')}', ${a.playbook_run_id})">Approve Action</button>
                    ` : (a.status === 'PENDING' ? `
                        <span style="font-size:0.8rem; color:var(--text-muted); align-self:center;">
                            Your tier (${USER_TIER}) is not authorized to approve. Minimum required: ${a.required_tier}.
                        </span>
                    ` : '')}
                    <button class="btn" onclick="closeModal('detailModal')">Close</button>
                `;

            } catch (err) {
                body.innerHTML = `<div style="padding:30px; text-align:center; color:var(--neon-red);">Error loading approval detail: ${escapeHtml(err.message)}</div>`;
            }
        }

        function renderRiskTable(risk) {
            if (!risk || !risk.factor_breakdown || !risk.factor_breakdown.length) {
                return '<div style="color:var(--text-muted); font-size:0.8rem; padding:10px 0;">No risk assessment breakdown recorded for this incident.</div>';
            }
            return `
                <table class="risk-table">
                    <thead>
                        <tr>
                            <th>Factor</th>
                            <th>Value</th>
                            <th>Contribution</th>
                            <th>Explanation</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${risk.factor_breakdown.map(f => `
                            <tr>
                                <td style="font-weight:600; color:#fff;">${escapeHtml(f.factor || '')}</td>
                                <td style="font-family:var(--font-mono); color:var(--neon-cyan);">${escapeHtml(String(f.value ?? ''))}</td>
                                <td style="font-family:var(--font-mono); font-weight:700; color:${(f.contribution || 0) > 0 ? 'var(--neon-amber)' : 'var(--text-muted)'};">
                                    +${f.contribution ?? 0} pts
                                </td>
                                <td style="color:var(--text-secondary);">${escapeHtml(f.explanation || '')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        function renderAlertsList(alerts) {
            if (!alerts || !alerts.length) return '<div style="color:var(--text-muted); font-size:0.8rem;">None</div>';
            return alerts.map(al => `
                <div style="border-bottom:1px solid rgba(13,110,253,0.1); padding:6px 0; font-size:0.75rem;">
                    <div style="display:flex; justify-content:space-between;">
                        <strong style="color:#fff;">${escapeHtml(al.category || 'Alert')}</strong>
                        <span style="color:var(--text-muted); font-family:var(--font-mono);">${escapeHtml(al.timestamp || '')}</span>
                    </div>
                    <div style="color:var(--text-secondary); margin-top:2px;">${escapeHtml(al.message || '')}</div>
                </div>
            `).join('');
        }

        function renderIocsList(iocs) {
            if (!iocs || !iocs.length) return '<div style="color:var(--text-muted); font-size:0.8rem;">None</div>';
            return iocs.map(ioc => `
                <div style="border-bottom:1px solid rgba(13,110,253,0.1); padding:6px 0; font-size:0.75rem; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-family:var(--font-mono); color:var(--neon-cyan);">${escapeHtml(ioc.ioc_value || '')}</div>
                        <div style="color:var(--text-muted); font-size:0.7rem;">${escapeHtml(ioc.ioc_type || '')}</div>
                    </div>
                    <div>
                        <span class="badge" style="background:#0B1A2E; color:${ioc.assessment==='MALICIOUS'?'var(--neon-red)':'var(--neon-amber)'};">${escapeHtml(ioc.assessment || 'UNKNOWN')}</span>
                    </div>
                </div>
            `).join('');
        }

        // Open Confirm Approve Modal
        function openApproveModal(id, actionName, incidentNum, runId) {
            activeApprovalId = id;
            document.getElementById('confirmActionName').textContent = actionName;
            document.getElementById('confirmIncidentNum').textContent = incidentNum || 'Incident #' + id;
            document.getElementById('confirmRunId').textContent = '#' + runId;
            openModal('confirmModal');
        }

        // Execute Approve
        document.getElementById('executeApproveBtn').addEventListener('click', async () => {
            const btn = document.getElementById('executeApproveBtn');
            btn.disabled = true;
            btn.textContent = 'Processing...';

            try {
                const res = await fetch('../api/v1/approvals.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                    body: JSON.stringify({
                        approval_id: activeApprovalId,
                        decision: 'APPROVE'
                    })
                });

                const json = await res.json();
                if (!res.ok || !json.success) {
                    throw new Error(json.message || 'Approval failed.');
                }

                closeModal('confirmModal');
                closeModal('detailModal');
                fetchQueue();
                fetchNotifications();
                alert('Action approved successfully. Playbook execution resumed.');
            } catch (err) {
                alert('Error approving action: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Authorize & Resume Playbook';
            }
        });

        // Open Reject Modal
        function openRejectModal(id) {
            activeApprovalId = id;
            document.getElementById('rejectReasonInput').value = '';
            document.getElementById('charCount').textContent = '0 / 1000';
            openModal('rejectModal');
        }

        document.getElementById('rejectReasonInput').addEventListener('input', (e) => {
            const len = e.target.value.length;
            document.getElementById('charCount').textContent = `${len} / 1000`;
        });

        // Execute Reject
        document.getElementById('executeRejectBtn').addEventListener('click', async () => {
            const reason = document.getElementById('rejectReasonInput').value.trim();
            if (reason.length < 10) {
                alert('Rejection reason must be at least 10 characters long.');
                return;
            }

            const btn = document.getElementById('executeRejectBtn');
            btn.disabled = true;
            btn.textContent = 'Rejecting...';

            try {
                const res = await fetch('../api/v1/approvals.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                    body: JSON.stringify({
                        approval_id: activeApprovalId,
                        decision: 'REJECT',
                        reason: reason
                    })
                });

                const json = await res.json();
                if (!res.ok || !json.success) {
                    throw new Error(json.message || 'Rejection failed.');
                }

                closeModal('rejectModal');
                closeModal('detailModal');
                fetchQueue();
                fetchNotifications();
                alert('Action rejected. Playbook run cancelled.');
            } catch (err) {
                alert('Error rejecting action: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Confirm Rejection';
            }
        });

        // Playbook Run Monitor Modal
        async function openRunMonitor(runId) {
            const body = document.getElementById('runMonitorBody');
            body.innerHTML = '<div style="text-align:center; padding:30px; color:var(--text-secondary);">Loading execution timeline...</div>';
            openModal('runMonitorModal');

            try {
                const res = await fetch(`../api/v1/playbook_runs_detail.php?id=${runId}`);
                if (!res.ok) throw new Error('Status ' + res.status);
                const json = await res.json();
                if (!json.success) throw new Error(json.message || 'Failed to load run.');

                const r = json.data.run;
                const steps = json.data.steps || [];
                const stepResults = json.data.step_results || [];

                document.getElementById('runMonitorTitle').textContent = `Playbook Run #${r.id} (${escapeHtml(r.run_uuid.substring(0, 8))}...)`;

                body.innerHTML = `
                    <div class="pane" style="margin-bottom:16px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <span class="badge badge-${escapeHtml(r.status)}">${escapeHtml(r.status)}</span>
                                <span style="font-family:var(--font-mono); font-size:0.8rem; margin-left:8px; color:var(--text-secondary);">
                                    Mode: ${escapeHtml(r.execution_context?.mode || 'MANUAL')} | Version: v${r.playbook_version ?? 1}
                                </span>
                            </div>
                            <div style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">
                                Started: ${escapeHtml(r.started_at || '')}
                            </div>
                        </div>
                    </div>

                    <div class="pane">
                        <div class="pane-heading">Step Execution Timeline</div>
                        <div class="timeline-list">
                            ${renderStepsTimeline(steps, stepResults, r)}
                        </div>
                    </div>
                `;

            } catch (e) {
                body.innerHTML = `<div style="padding:20px; text-align:center; color:var(--neon-red);">Error loading run: ${escapeHtml(e.message)}</div>`;
            }
        }

        function renderStepsTimeline(steps, results, run) {
            if (!steps.length) return '<div style="color:var(--text-muted);">No steps defined.</div>';
            const resultMap = {};
            results.forEach(res => {
                resultMap[res.step_order] = res;
            });

            return steps.map(s => {
                const res = resultMap[s.step_order];
                let icon = '○';
                let statusLabel = 'PENDING';
                let statusColor = 'var(--text-muted)';

                if (res) {
                    if (res.status === 'SUCCESS') {
                        icon = '✓'; statusLabel = 'COMPLETED'; statusColor = 'var(--neon-green)';
                    } else if (res.status === 'WAITING_APPROVAL') {
                        icon = '⏳'; statusLabel = 'WAITING APPROVAL'; statusColor = 'var(--neon-amber)';
                    } else if (res.status === 'FAILED') {
                        icon = '✕'; statusLabel = 'FAILED'; statusColor = 'var(--neon-red)';
                    }
                } else if (run.status === 'RUNNING' && run.current_step_order == s.step_order) {
                    icon = '▶'; statusLabel = 'EXECUTING'; statusColor = 'var(--neon-cyan)';
                }

                return `
                    <div class="timeline-step">
                        <div class="step-num" style="color:${statusColor}; font-size:1.1rem;">${icon}</div>
                        <div class="step-info">
                            <div class="step-name">${escapeHtml(s.step_name)} <span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--neon-cyan);">(${escapeHtml(s.action_type)})</span></div>
                            <div class="step-meta">Order: ${s.step_order} | Timeout: ${s.timeout_seconds}s | Status: <strong style="color:${statusColor};">${statusLabel}</strong></div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Modal Helpers
        function openModal(id) { document.getElementById(id).classList.add('open'); }
        function closeModal(id) { document.getElementById(id).classList.remove('open'); }

        // Escape HTML
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }

        const requestedApproval = new URLSearchParams(window.location.search).get('approval_id');
        if (requestedApproval && /^[1-9][0-9]*$/.test(requestedApproval) && Number.isSafeInteger(Number(requestedApproval))) {
            openDetail(Number(requestedApproval));
        }

        // Setup Events & Polling
        function resetQueue() { clearTimeout(searchTimer); queuePage = 1; fetchQueue(); }
        for (const id of ['statusFilter','priorityFilter','kindFilter','sortFilter']) document.getElementById(id).addEventListener('change', resetQueue);
        document.getElementById('searchInput').addEventListener('input', () => {
            clearTimeout(searchTimer);
            ++queueRequest;
            if (queueController) queueController.abort();
            searchTimer = setTimeout(resetQueue, 300);
        });
        document.getElementById('queuePrevious').addEventListener('click', () => { if (queuePage > 1) { --queuePage; fetchQueue(); } });
        document.getElementById('queueNext').addEventListener('click', () => { if (queuePage < queuePages) { ++queuePage; fetchQueue(); } });
        document.getElementById('refreshBtn').addEventListener('click', () => { fetchQueue(); fetchNotifications(); });

        document.getElementById('bellBtn').addEventListener('click', (e) => {
            e.stopPropagation();
            document.getElementById('notifPopup').classList.toggle('open');
        });
        document.addEventListener('click', (e) => {
            const popup = document.getElementById('notifPopup');
            if (!popup.contains(e.target) && e.target !== document.getElementById('bellBtn')) {
                popup.classList.remove('open');
            }
        });

        // Polling with Visibility API (Correction 3)
        function startPolling() {
            if (pollTimer) clearInterval(pollTimer);
            pollTimer = setInterval(() => {
                if (!document.hidden) {
                    fetchQueue();
                    fetchNotifications();
                }
            }, 8000);
        }

        document.addEventListener('visibilitychange', () => {
            const statusText = document.getElementById('pollStatusText');
            if (document.hidden) {
                if (statusText) statusText.textContent = 'POLLING PAUSED';
            } else {
                if (statusText) statusText.textContent = 'LIVE MONITORING';
                fetchQueue();
                fetchNotifications();
            }
        });

        // Initial Load
        fetchQueue();
        fetchNotifications();
        startPolling();
    </script>
</body>
</html>
