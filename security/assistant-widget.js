(() => {
  'use strict';
  const widget = document.querySelector('.assistant-widget');
  if (!widget || !window.CyberShieldAssistant) return;

  const launcher = widget.querySelector('.assistant-launcher');
  const panel = widget.querySelector('.assistant-widget-panel');
  const closeButton = widget.querySelector('.assistant-widget-close');
  const form = widget.querySelector('.assistant-widget-form');
  const question = form.querySelector('textarea[name="question"]');
  const eventId = form.querySelector('input[name="event_id"]');
  const selection = form.querySelector('.assistant-widget-selection');
  const submit = form.querySelector('button[type="submit"]');
  const response = widget.querySelector('.assistant-widget-response');
  const metadata = widget.querySelector('.assistant-widget-meta');
  const cancel = form.querySelector('[data-assistant-cancel]');
  let controller = null;

  function setOpen(open) {
    panel.hidden = !open;
    launcher.setAttribute('aria-expanded', String(open));
    if (open) question.focus();
    else launcher.focus();
  }

  launcher.addEventListener('click', () => setOpen(panel.hidden));
  closeButton.addEventListener('click', () => setOpen(false));
  cancel.addEventListener('click', () => controller?.abort());
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !panel.hidden) setOpen(false);
  });

  document.addEventListener('click', (event) => {
    const trigger = event.target.closest('.assistant-event-context');
    if (!trigger || controller) return;
    eventId.value = trigger.dataset.eventId || '';
    selection.hidden = !eventId.value;
    selection.textContent = eventId.value ? 'Contexte sélectionné : métadonnées de cette alerte.' : '';
    question.value = 'Explique cette alerte';
    response.hidden = true;
    metadata.hidden = true;
    setOpen(true);
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (controller) return;
    if (!form.reportValidity()) return;
    controller = new AbortController();
    const started = performance.now();
    let timedOut = false;
    const timer = window.setTimeout(() => { timedOut = true; controller.abort(); },
      window.CyberShieldAssistant.timeoutMs(widget.dataset.timeoutMs));
    submit.disabled = true;
    submit.setAttribute('aria-busy', 'true');
    submit.textContent = 'Analyse…';
    cancel.hidden = false;
    metadata.hidden = true;
    response.hidden = false;
    response.classList.remove('is-error');
    response.textContent = 'Question envoyée. Tu peux continuer à naviguer ou annuler l’attente.';
    try {
      const payload = await window.CyberShieldAssistant.ask(widget.dataset.endpoint, form, controller.signal);
      window.CyberShieldAssistant.renderAnswer(response, payload.answer);
      metadata.textContent = window.CyberShieldAssistant.sourceLabel(payload) + ' · '
        + ((performance.now() - started) / 1000).toLocaleString('fr-FR', { maximumFractionDigits: 2 }) + ' s';
      metadata.hidden = false;
      eventId.value = '';
      selection.hidden = true;
      question.focus();
    } catch (error) {
      response.classList.add('is-error');
      response.textContent = controller.signal.aborted
        ? (timedOut ? 'Le délai est dépassé. Essaie le bilan rapide ou une question plus courte.' : 'Attente annulée.')
        : (error instanceof Error ? error.message : 'Le service local est indisponible.');
    } finally {
      window.clearTimeout(timer);
      controller = null;
      cancel.hidden = true;
      submit.disabled = false;
      submit.removeAttribute('aria-busy');
      submit.textContent = 'Envoyer →';
    }
  });
})();
