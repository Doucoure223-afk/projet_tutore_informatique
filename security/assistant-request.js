(() => {
  'use strict';

  function sourceLabel(payload) {
    return payload.source === 'local' ? 'Réponse locale · données autorisées' : 'Analyse du modèle local';
  }

  async function ask(endpoint, form, signal) {
    const url = new URL(endpoint, window.location.href);
    if (url.origin !== window.location.origin) throw new Error('Adresse de l’assistant non autorisée.');
    const result = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Accept': 'application/json' },
      body: new URLSearchParams(new FormData(form)),
      cache: 'no-store',
      signal,
    });
    let payload;
    try { payload = await result.json(); }
    catch { throw new Error('La session ou le service ne répond plus. Recharge la page avant de réessayer.'); }
    if (!result.ok || !payload || payload.ok !== true || typeof payload.answer !== 'string') {
      throw new Error(payload && typeof payload.error === 'string' ? payload.error : 'La réponse n’a pas pu être obtenue.');
    }
    return payload;
  }

  function timeoutMs(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 6000 && parsed <= 24000 ? parsed : 14000;
  }

  // Model output remains untrusted. Create only these fixed DOM elements and
  // text nodes; HTML and links from the answer never become executable markup.
  function renderAnswer(container, answer) {
    const doc = container.ownerDocument || document;
    container.replaceChildren();
    container.classList.add('assistant-prose');
    const lines = String(answer).replace(/\r\n?/g, '\n').split('\n');
    let paragraph = null;
    let list = null;
    let fence = null;

    function inline(parent, value) {
      const tokens = /`([^`\n]+)`|\*\*([^*\n]+)\*\*|__([^_\n]+)__/g;
      let start = 0;
      for (const match of value.matchAll(tokens)) {
        parent.appendChild(doc.createTextNode(value.slice(start, match.index)));
        const node = doc.createElement(match[1] !== undefined ? 'code' : 'strong');
        node.textContent = match[1] ?? match[2] ?? match[3];
        parent.appendChild(node);
        start = match.index + match[0].length;
      }
      parent.appendChild(doc.createTextNode(value.slice(start)));
    }

    function codeBlock() {
      const pre = doc.createElement('pre');
      const code = doc.createElement('code');
      code.textContent = fence.join('\n');
      pre.appendChild(code);
      container.appendChild(pre);
      fence = null;
    }

    for (const line of lines) {
      if (/^\s*```/.test(line)) {
        paragraph = null;
        list = null;
        if (fence) codeBlock();
        else fence = [];
        continue;
      }
      if (fence) { fence.push(line); continue; }
      const value = line.trim();
      if (!value) { paragraph = null; list = null; continue; }
      const heading = value.match(/^#{1,6}\s+(.+)$/)
        || value.match(/^\*\*([^*]+)\*\*(\s*(?:\([^)]*\))?\s*:?)$/)
        || value.match(/^\*\*([^*]+)$/);
      if (heading) {
        paragraph = null;
        list = null;
        const node = doc.createElement('h3');
        inline(node, heading[1] + (heading[2] || ''));
        container.appendChild(node);
        continue;
      }
      const item = value.match(/^([-*+•]|\d+[.)])\s+(.+)$/);
      if (item) {
        paragraph = null;
        const kind = /^\d/.test(item[1]) ? 'OL' : 'UL';
        if (!list || list.tagName !== kind) {
          list = doc.createElement(kind.toLowerCase());
          container.appendChild(list);
        }
        const node = doc.createElement('li');
        inline(node, item[2]);
        list.appendChild(node);
        continue;
      }
      list = null;
      if (!paragraph) {
        paragraph = doc.createElement('p');
        container.appendChild(paragraph);
      } else paragraph.appendChild(doc.createElement('br'));
      inline(paragraph, line);
    }
    if (fence) codeBlock();
  }

  window.CyberShieldAssistant = Object.freeze({ ask, sourceLabel, timeoutMs, renderAnswer });
})();
