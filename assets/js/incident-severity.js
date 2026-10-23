(() => {
    const form = document.getElementById('severity-form');
    if (!form) return;
    const feedback = document.getElementById('severity-feedback');
    form.addEventListener('submit', async event => {
        event.preventDefault();
        const data = new FormData(form);
        const reason = String(data.get('reason') || '').trim();
        if (!reason || new TextEncoder().encode(reason).length > 2000) {
            feedback.textContent = 'Provide a reason of at most 2,000 UTF-8 bytes.';
            return;
        }
        const button = form.querySelector('button[type="submit"]');
        button.disabled = true;
        feedback.textContent = 'Saving severity assessment…';
        try {
            const response = await fetch('api/v1/incident_severity.php', {
                method: 'POST', credentials: 'same-origin',
                headers: {'Content-Type':'application/json','X-CSRF-Token':String(data.get('csrf_token') || '')},
                body: JSON.stringify({incident_id:Number(form.dataset.incidentId), severity:String(data.get('severity')), expected_severity:form.dataset.severity, expected_priority:form.dataset.priority, reason})
            });
            const result = await response.json();
            if (!response.ok || !result.success) {
                feedback.textContent = result.message || 'Severity update failed. Your reason is retained.';
                if (response.status === 409) {
                    const reload = document.createElement('a');
                    reload.href = window.location.href; reload.textContent = 'Reload case';
                    feedback.append(' ',reload);
                }
                return;
            }
            if (!result.data.changed) {
                feedback.textContent = 'Severity is already set to this value. Priority and history were left unchanged. Reload to see the latest case.';
                const reload = document.createElement('a');reload.href = window.location.href;reload.textContent = 'Reload case';feedback.append(' ',reload);
                return;
            }
            window.location.reload();
        } catch (_) {
            feedback.textContent = 'Could not confirm the update. Your reason is retained; check the case before retrying.';
        } finally { button.disabled = false; }
    });
})();
