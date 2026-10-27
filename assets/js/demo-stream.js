(() => {
  const root = document.getElementById('demo-stream');
  if (!root) return;
  const start = document.getElementById('stream-start');
  const stop = document.getElementById('stream-stop');
  const interval = document.getElementById('stream-interval');
  const status = document.getElementById('stream-status');
  const results = document.getElementById('stream-results');
  let running = false, pending = false, timer, deadline, batches = 0;
  // Retain an uncertain request key so restarting after a network error cannot
  // create a second case for an already committed batch.
  let requestKey = null;
  const key = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), x => x.toString(16).padStart(2, '0')).join('');
  function halt(message) {
    running = false;
    clearTimeout(timer);
    start.disabled = pending;
    stop.disabled = true;
    interval.disabled = pending;
    status.textContent = message;
  }
  async function tick() {
    if (!running) return;
    if (Date.now() >= deadline) return halt('Stopped after 15 minutes. Saved simulated cases: ' + batches + '.');
    pending = true;
    requestKey ||= key();
    status.textContent = 'Creating simulated batch… Saved cases this visit: ' + batches + '.';
    try {
      const response = await fetch('demo.php', {
        method: 'POST', credentials: 'same-origin',
        body: new URLSearchParams({action: 'create', request_key: requestKey, csrf_token: root.dataset.csrf})
      });
      const html = await response.text();
      const destination = new URL(response.url);
      if (!response.ok || !destination.pathname.endsWith('/demo.php') || !/^\d+$/.test(destination.searchParams.get('id') || '')) {
        const doc = new DOMParser().parseFromString(html, 'text/html');
        throw new Error(doc.querySelector('section.error')?.textContent.trim() || 'Check your login, permissions, detection rule and database health.');
      }
      requestKey = null;
      batches++;
      const item = document.createElement('li');
      const link = document.createElement('a');
      link.href = 'demo.php?id=' + destination.searchParams.get('id');
      link.target = '_blank'; link.rel = 'noopener';
      link.textContent = 'Simulated batch ' + batches + ' · ' + new Date().toLocaleTimeString() + ' · Open investigation';
      item.append(link); results.prepend(item);
      if (results.children.length > 20) results.lastElementChild.remove();
      status.textContent = (running ? 'Running. ' : 'Stopped. Final in-flight batch completed. ') + 'Saved simulated cases: ' + batches + '.';
    } catch (error) {
      halt('Stream stopped: ' + error.message + ' Restart retries the same batch safely.');
    } finally {
      pending = false;
      if (!running) { start.disabled = false; interval.disabled = false; }
    }
    if (running) timer = setTimeout(tick, Number(interval.value) * 1000);
  }
  start.addEventListener('click', () => {
    if (running || pending) return;
    running = true; deadline = Date.now() + 15 * 60 * 1000;
    start.disabled = true; interval.disabled = true; stop.disabled = false;
    tick();
  });
  stop.addEventListener('click', () => halt(pending
    ? 'Stopping. The in-flight batch may finish; no further batches will start.'
    : 'Stopped. Saved simulated cases: ' + batches + '.'));
  window.addEventListener('pagehide', () => halt('Stopped when leaving the page.'));
})();
