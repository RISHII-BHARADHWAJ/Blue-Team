// Runs in the head before paint; a stored choice takes priority over the OS.
(() => {
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let choice = null;
  try { choice = localStorage.getItem('threatpulse-theme'); } catch (_) {}
  if (!['light', 'dark'].includes(choice)) choice = null;
  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.textContent = theme === 'dark' ? '☀ Light' : '☾ Dark';
      button.setAttribute('aria-label', 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' mode');
    });
  }
  apply(choice || (media.matches ? 'dark' : 'light'));
  document.addEventListener('DOMContentLoaded', () => {
    apply(document.documentElement.dataset.theme);
    document.querySelectorAll('[data-theme-toggle]').forEach(button => button.addEventListener('click', () => {
      choice = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem('threatpulse-theme', choice); } catch (_) {}
      apply(choice);
    }));
  });
  media.addEventListener('change', () => { if (!choice) apply(media.matches ? 'dark' : 'light'); });
  window.addEventListener('storage', event => {
    if (event.key !== 'threatpulse-theme') return;
    choice = ['light', 'dark'].includes(event.newValue) ? event.newValue : null;
    apply(choice || (media.matches ? 'dark' : 'light'));
  });
})();
