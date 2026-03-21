// ── CLOCK ─────────────────────────────
function updateClock() {
    const el = document.getElementById('statusTime');
    if (el) {
        const now = new Date();
        el.textContent = 'UPDATED: ' 
            + now.toUTCString().slice(17,25) + ' UTC';
    }
}
setInterval(updateClock, 1000);
updateClock();

// ── COUNTER ANIMATION ─────────────────
setTimeout(() => {
    document.querySelectorAll('.metric-value, .gauge-value')
    .forEach(el => {
        const target = parseInt(el.dataset.target) || 0;
        let cur = 0;
        const step = Math.max(1, Math.ceil(target / 60));
        const timer = setInterval(() => {
            cur = Math.min(cur + step, target);
            el.textContent = cur.toLocaleString();
            if (cur >= target) clearInterval(timer);
        }, 25);
    });
}, 100);

// ── GAUGE CANVAS ──────────────────────
(function drawGauge() {
    const canvas = document.getElementById('gaugeCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const val = parseInt(
        document.querySelector('.gauge-value')?.dataset.target) || 0;
    const pct = val / 15;
    const cx = 100, cy = 95, r = 70;

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, 2*Math.PI);
    ctx.strokeStyle = 'rgba(13,110,253,0.15)';
    ctx.lineWidth = 14;
    ctx.stroke();

    // Value arc (gradient green→red)
    const grad = ctx.createLinearGradient(30,95,170,95);
    grad.addColorStop(0,   '#00FF9C');
    grad.addColorStop(0.5, '#FFB700');
    grad.addColorStop(1,   '#FF3B3B');
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, Math.PI + (Math.PI * pct));
    ctx.strokeStyle = grad;
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.stroke();
})();

// ── CHART.JS BAR CHART ────────────────
document.addEventListener('DOMContentLoaded', function() {
    const canvas = document.getElementById('attackChart');
    if (!canvas || typeof Chart === 'undefined') return;

    const colors = CHART_LABELS.map(l => 
        CHART_COLORS[l] || '#0D6EFD');

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: CHART_LABELS,
            datasets: [{
                data: CHART_DATA,
                backgroundColor: colors.map(c => c + '33'),
                borderColor: colors,
                borderWidth: 2,
                borderRadius: 6,
                hoverBackgroundColor: colors.map(c => c + '77'),
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false },
                tooltip: {
                    backgroundColor: '#050F1F',
                    borderColor: '#0D6EFD',
                    borderWidth: 1,
                    titleColor: '#E0EEFF',
                    bodyColor: '#7BA3CC',
                }
            },
            scales: {
                x: { grid:{color:'rgba(13,110,253,0.08)'},
                     ticks:{color:'#7BA3CC',
                     font:{family:'Share Tech Mono'}} },
                y: { grid:{color:'rgba(13,110,253,0.08)'},
                     ticks:{color:'#7BA3CC',
                     font:{family:'Share Tech Mono'}},
                     beginAtZero:true }
            },
            animation:{ duration:1000, easing:'easeInOutQuart' }
        }
    });

    // ── LOG ROW CLICK → TERMINAL ──────────
    document.querySelectorAll('.log-row').forEach(row => {
        row.addEventListener('click', function() {
            const token = this.dataset.token;
            if (!token) return;
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'terminal.php';
            const t = document.createElement('input');
            t.type = 'hidden'; t.name = 'token'; t.value = token;
            const c = document.createElement('input');
            c.type = 'hidden'; c.name = 'csrf_token';
            // Adjusted ID finding since the field might be nested or named slightly differently
            c.value = document.getElementById('csrfToken') ? document.getElementById('csrfToken').value : '';
            form.appendChild(t); form.appendChild(c);
            document.body.appendChild(form);
            form.submit();
        });
    });
});
