(() => {
  'use strict';
  const widget = document.querySelector('.assistant-widget');
  if (!widget) return;

  const launcher = widget.querySelector('.assistant-launcher');
  const panel = widget.querySelector('.assistant-widget-panel');
  const closeButton = widget.querySelector('.assistant-widget-close');
  const form = widget.querySelector('.assistant-widget-form');
  const question = form.querySelector('textarea[name="question"]');
  const submit = form.querySelector('button[type="submit"]');
  const response = widget.querySelector('.assistant-widget-response');

  function setOpen(open) {
    panel.hidden = !open;
    launcher.setAttribute('aria-expanded', String(open));
    if (open) question.focus();
    else launcher.focus();
  }

  launcher.addEventListener('click', () => setOpen(panel.hidden));
  closeButton.addEventListener('click', () => setOpen(false));
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !panel.hidden) setOpen(false);
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    submit.disabled = true;
    submit.textContent = 'Envoi…';
    response.hidden = false;
    response.classList.remove('is-error');
    response.textContent = 'Le modèle local prépare une réponse…';
    try {
      const body = new URLSearchParams(new FormData(form));
      const result = await fetch(widget.dataset.endpoint, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Accept': 'application/json' },
        body,
        cache: 'no-store',
      });
      const payload = await result.json();
      if (!result.ok || !payload || payload.ok !== true || typeof payload.answer !== 'string') {
        throw new Error(payload && typeof payload.error === 'string' ? payload.error : 'La réponse n’a pas pu être obtenue.');
      }
      response.textContent = payload.answer;
      question.value = '';
      question.focus();
    } catch (error) {
      response.classList.add('is-error');
      response.textContent = error instanceof Error ? error.message : 'Le service local est indisponible.';
    } finally {
      submit.disabled = false;
      submit.textContent = 'Envoyer →';
    }
  });
})();
