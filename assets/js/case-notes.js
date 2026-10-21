'use strict';
(() => {
    const form = document.getElementById('case-note-form');
    if (!form) return;
    const feedback = document.getElementById('case-note-feedback');
    const field = form.elements.note;
    const button = form.querySelector('button[type="submit"]');
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!field.value.trim()) { feedback.textContent = 'Write a note before saving.'; field.focus(); return; }
        button.disabled = true;
        feedback.textContent = 'Saving case note…';
        try {
            const response = await fetch('api/v1/case_notes.php', {
                method: 'POST', credentials: 'same-origin',
                headers: {'Content-Type':'application/json', 'X-CSRF-Token':form.elements.csrf_token.value},
                body: JSON.stringify({incident_id:Number(form.dataset.incidentId), note:field.value})
            });
            const result = await response.json();
            if (!response.ok || !result.success) throw new Error(result.error || result.message || 'Could not save this note.');
            feedback.textContent = 'Saved. Refreshing the case…';
            const url = new URL(window.location.href);
            url.searchParams.delete('notes_page');
            url.hash = 'case-notes';
            window.history.replaceState(null, '', url.toString());
            window.location.reload();
        } catch (error) {
            feedback.textContent = error.message + ' Your text is still here. If the connection failed, check the case before retrying.';
            button.disabled = false;
        }
    });
})();
