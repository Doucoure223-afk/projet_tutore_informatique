(() => {
  'use strict';
  const form = document.querySelector('.assistant-form');
  if (!form || !window.CyberShieldAssistant) return;

  const submit = form.querySelector('button[type="submit"]');
  const pending = document.getElementById('assistant-pending');
  const cancel = form.querySelector('[data-assistant-cancel]');
  const question = form.querySelector('textarea');
  const suggestions = form.querySelectorAll('[data-question]');
  const errorBox = document.getElementById('assistant-error');
  const result = document.getElementById('assistant-result');
  const answer = document.getElementById('assistant-answer');
  const source = document.getElementById('assistant-answer-source');
  const timing = document.getElementById('assistant-answer-timing');
  const idleLabel = submit.textContent;
  let controller = null;
  if (answer.textContent.trim()) {
    window.CyberShieldAssistant.renderAnswer(answer, answer.textContent);
  }

  cancel.addEventListener('click', () => controller?.abort());
  suggestions.forEach((button) => button.addEventListener('click', () => {
    if (controller) return;
    question.value = button.dataset.question;
    form.requestSubmit();
  }));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (controller) return;
    if (!form.reportValidity()) return;
    controller = new AbortController();
    const started = performance.now();
    let timedOut = false;
    const timer = window.setTimeout(() => { timedOut = true; controller.abort(); },
      window.CyberShieldAssistant.timeoutMs(form.dataset.timeoutMs));
    submit.disabled = true;
    suggestions.forEach((button) => { button.disabled = true; });
    submit.setAttribute('aria-busy', 'true');
    submit.textContent = 'Analyse en cours…';
    cancel.hidden = false;
    errorBox.hidden = true;
    result.hidden = true;
    pending.textContent = 'Question envoyée. Tu peux continuer à naviguer ou annuler l’attente.';
    pending.hidden = false;
    try {
      const payload = await window.CyberShieldAssistant.ask(form.dataset.endpoint, form, controller.signal);
      window.CyberShieldAssistant.renderAnswer(answer, payload.answer);
      source.textContent = window.CyberShieldAssistant.sourceLabel(payload);
      timing.textContent = ((performance.now() - started) / 1000).toLocaleString('fr-FR', { maximumFractionDigits: 2 }) + ' s';
      result.hidden = false;
      result.scrollIntoView?.({ block: 'start', behavior: 'auto' });
    } catch (error) {
      if (controller.signal.aborted) {
        pending.textContent = timedOut
          ? 'Le délai est dépassé. Essaie le bilan rapide ou une question plus courte.'
          : 'Attente annulée. Tu peux poser une autre question.';
      } else {
        errorBox.querySelector('p').textContent = error instanceof Error ? error.message : 'Le service local est indisponible.';
        errorBox.hidden = false;
      }
    } finally {
      window.clearTimeout(timer);
      if (!controller.signal.aborted) pending.hidden = true;
      controller = null;
      cancel.hidden = true;
      submit.disabled = false;
      submit.removeAttribute('aria-busy');
      submit.textContent = idleLabel;
      suggestions.forEach((button) => { button.disabled = false; });
    }
  });
})();
