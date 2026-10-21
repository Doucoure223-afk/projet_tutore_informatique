'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const scripts = (name) => fs.readFileSync(path.join(__dirname, '..', 'security', name), 'utf8');

class Element {
  constructor(text = '') {
    this.childNodes = [];
    this.textContent = text;
    this.value = '';
    this.hidden = false;
    this.disabled = false;
    this.dataset = {};
    this.attributes = new Map();
    this.listeners = new Map();
    this.children = new Map();
    this.classes = new Set();
    this.classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      contains: (name) => this.classes.has(name),
    };
  }
  get textContent() { return this._text + this.childNodes.map((node) => node.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.childNodes = []; }
  appendChild(node) { this.childNodes.push(node); return node; }
  replaceChildren(...nodes) { this._text = ''; this.childNodes = [...nodes]; }
  set innerHTML(_) { throw new Error('Untrusted content must be rendered as text.'); }
  addEventListener(type, handler) {
    this.listeners.set(type, [...(this.listeners.get(type) || []), handler]);
  }
  async fire(type, event = {}) {
    event.target ||= this;
    event.defaultPrevented = false;
    event.preventDefault = () => { event.defaultPrevented = true; };
    await Promise.all((this.listeners.get(type) || []).map((handler) => handler(event)));
    return event;
  }
  querySelector(selector) { return this.children.get(selector) || null; }
  querySelectorAll(selector) { return this.children.get(selector) || []; }
  setAttribute(name, value) { this.attributes.set(name, value); }
  removeAttribute(name) { this.attributes.delete(name); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  focus() { this.focused = true; }
  reportValidity() { return this.valid !== false; }
  requestSubmit() { return this.fire('submit'); }
  closest(selector) { return this.matches === selector ? this : null; }
}

function environment() {
  const document = new Element();
  document.ids = new Map();
  document.getElementById = (id) => document.ids.get(id) || null;
  document.createElement = (tag) => { const node = new Element(); node.tagName = tag.toUpperCase(); node.ownerDocument = document; return node; };
  document.createTextNode = (text) => { const node = new Element(text); node.tagName = '#text'; return node; };
  const timers = new Map();
  let timerId = 0;
  const window = {
    location: { href: 'http://127.0.0.1:8080/security/assistant.php', origin: 'http://127.0.0.1:8080' },
    setTimeout: (callback, delay) => { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout: (id) => timers.delete(id),
  };
  const context = vm.createContext({ window, document, URL, URLSearchParams, AbortController, Error,
    performance: { now: () => 1250 },
    FormData: class FormData {
      constructor(form) { this.entries = form.entries || []; }
      [Symbol.iterator]() { return this.entries[Symbol.iterator](); }
    },
  });
  return { window, document, context, timers, run: (name) => vm.runInContext(scripts(name), context, { filename: name }) };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function installRequester(env) {
  const requests = [];
  env.run('assistant-request.js');
  env.window.CyberShieldAssistant = {
    ...env.window.CyberShieldAssistant,
    timeoutMs: (value) => { const number = Number(value); return number >= 6000 && number <= 24000 ? number : 14000; },
    sourceLabel: (payload) => payload.source === 'local' ? 'Réponse locale · données autorisées' : 'Analyse du modèle local',
    ask: (endpoint, form, signal) => {
      const pending = deferred();
      requests.push({ endpoint, form, signal, ...pending });
      signal.addEventListener('abort', () => pending.reject(new Error('aborted')), { once: true });
      return pending.promise;
    },
  };
  return requests;
}

function pageHarness() {
  const env = environment();
  const form = new Element();
  form.dataset = { endpoint: '/security/assistant-api.php', timeoutMs: '14000' };
  const submit = new Element('Analyser avec l’assistant');
  const cancel = new Element();
  cancel.hidden = true;
  const question = new Element();
  const suggestion = new Element();
  suggestion.dataset.question = 'Quel est le bilan ?';
  form.children.set('button[type="submit"]', submit);
  form.children.set('[data-assistant-cancel]', cancel);
  form.children.set('textarea', question);
  form.children.set('[data-question]', [suggestion]);
  env.document.children.set('.assistant-form', form);
  const ids = ['assistant-pending', 'assistant-error', 'assistant-result', 'assistant-answer', 'assistant-answer-source', 'assistant-answer-timing'];
  for (const id of ids) env.document.ids.set(id, new Element());
  const error = env.document.getElementById('assistant-error');
  const errorText = new Element();
  error.children.set('p', errorText);
  const requests = installRequester(env);
  env.run('assistant-page.js');
  return { ...env, form, submit, cancel, question, suggestion, error, errorText, requests,
    pending: env.document.getElementById('assistant-pending'),
    result: env.document.getElementById('assistant-result'),
    answer: env.document.getElementById('assistant-answer'),
    source: env.document.getElementById('assistant-answer-source') };
}

function assertPageIdle(ui) {
  assert.equal(ui.submit.disabled, false);
  assert.equal(ui.submit.textContent, 'Analyser avec l’assistant');
  assert.equal(ui.submit.getAttribute('aria-busy'), null);
  assert.equal(ui.cancel.hidden, true);
  assert.equal(ui.suggestion.disabled, false);
  assert.equal(ui.timers.size, 0);
}

test('request helper uses one same-origin form POST with the supplied abort signal', async () => {
  const env = environment();
  const calls = [];
  env.context.fetch = async (...args) => { calls.push(args); return { ok: true, json: async () => ({ ok: true, answer: 'Bonjour', source: 'local' }) }; };
  env.run('assistant-request.js');
  const controller = new AbortController();
  const payload = await env.window.CyberShieldAssistant.ask('/security/assistant-api.php', { entries: [['question', 'bilan & détails'], ['csrf_token', 'test-token']] }, controller.signal);
  assert.equal(payload.answer, 'Bonjour');
  assert.equal(calls.length, 1);
  const [url, options] = calls[0];
  assert.equal(url.href, 'http://127.0.0.1:8080/security/assistant-api.php');
  assert.equal(options.method, 'POST');
  assert.equal(options.credentials, 'same-origin');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.headers.Accept, 'application/json');
  assert.match(options.headers['Content-Type'], /^application\/x-www-form-urlencoded/);
  assert.equal(options.body.get('question'), 'bilan & détails');
  assert.equal(options.body.get('csrf_token'), 'test-token');
  assert.equal(options.signal, controller.signal);
  await assert.rejects(env.window.CyberShieldAssistant.ask('https://other.example/collect', {}, controller.signal), /non autorisée/);
  assert.equal(calls.length, 1, 'foreign endpoints must not receive any request');
});

test('request helper never retries 429 and handles invalid JSON/session responses', async () => {
  const env = environment();
  let calls = 0;
  env.context.fetch = async () => { calls++; return { ok: false, status: 429, json: async () => ({ ok: false, error: 'Assistant déjà occupé.' }) }; };
  env.run('assistant-request.js');
  await assert.rejects(env.window.CyberShieldAssistant.ask('/api', {}), /déjà occupé/);
  assert.equal(calls, 1);
  env.context.fetch = async () => ({ ok: true, json: async () => { throw new SyntaxError('HTML login page'); } });
  await assert.rejects(env.window.CyberShieldAssistant.ask('/api', {}), /session ou le service/);
  env.context.fetch = async () => ({ ok: true, json: async () => ({ ok: true, answer: 42 }) });
  await assert.rejects(env.window.CyberShieldAssistant.ask('/api', {}), /n’a pas pu/);
});

test('source labels preserve provenance and timeout values stay within 6–24 seconds', () => {
  const env = environment();
  env.run('assistant-request.js');
  const helper = env.window.CyberShieldAssistant;
  assert.match(helper.sourceLabel({ source: 'local' }), /Réponse locale/);
  assert.match(helper.sourceLabel({ source: 'llm' }), /modèle local/);
  assert.notEqual(helper.sourceLabel({ source: 'local' }), helper.sourceLabel({ source: 'llm' }));
  for (const value of [undefined, '', 'invalid', -1, 5999, 24001, Infinity]) assert.equal(helper.timeoutMs(value), 14000);
  for (const value of [6000, '14000', 24000]) assert.equal(helper.timeoutMs(value), Number(value));
  assert.equal(Object.isFrozen(helper), true);
});

test('answers render headings, lists and inline emphasis without exposing Markdown markers', () => {
  const env = environment();
  env.run('assistant-request.js');
  const answer = new Element();
  env.window.CyberShieldAssistant.renderAnswer(answer,
    'Voici le bilan.\n\n**Bloqués** (0)\n\n* Aucun événement bloqué\n* Le filtre reste en **observation**.\n\n### Étapes\n1. Lire le journal\n2. Vérifier `MODE`');
  assert.deepEqual(answer.childNodes.map((node) => node.tagName), ['P', 'H3', 'UL', 'H3', 'OL']);
  assert.equal(answer.childNodes[1].textContent, 'Bloqués (0)');
  assert.equal(answer.childNodes[2].childNodes.length, 2);
  const tags = (node) => [node.tagName, ...node.childNodes.flatMap(tags)];
  assert.ok(tags(answer).includes('STRONG'));
  assert.ok(tags(answer).includes('CODE'));
  assert.doesNotMatch(answer.textContent, /\*\*|`MODE`/);
  assert.equal(answer.classList.contains('assistant-prose'), true);
});

test('formatted HTML, links and fenced code remain inert, including incomplete output', () => {
  const env = environment();
  env.run('assistant-request.js');
  const answer = new Element();
  const hostile = '<img src=x onerror="alert(1)">';
  env.window.CyberShieldAssistant.renderAnswer(answer,
    '**' + hostile + '**\n\n- [Ouvrir](javascript:alert(1))\n\n```html\n<script>alert(1)</script>\n```\n\n**Signaux');
  const tags = (node) => [node.tagName, ...node.childNodes.flatMap(tags)];
  assert.ok(!tags(answer).some((tag) => ['IMG', 'SCRIPT', 'SVG', 'A', 'IFRAME'].includes(tag)));
  assert.match(answer.textContent, /<img src=x onerror=/);
  assert.match(answer.textContent, /javascript:alert/);
  assert.equal(answer.childNodes.at(-1).textContent, 'Signaux');
  env.window.CyberShieldAssistant.renderAnswer(answer, '```sql\nSELECT 1;');
  assert.equal(answer.childNodes[0].tagName, 'PRE');
  assert.equal(answer.childNodes[0].textContent, 'SELECT 1;');
  assert.doesNotMatch(answer.textContent, /Signaux/);
});

test('page prevents navigation and duplicate submits; results remain text with accurate source', async () => {
  const ui = pageHarness();
  const event = {};
  const submission = ui.form.fire('submit', event);
  assert.equal(event.defaultPrevented, true);
  assert.equal(ui.submit.disabled, true);
  assert.equal(ui.cancel.hidden, false);
  assert.equal(ui.suggestion.disabled, true);
  await ui.form.fire('submit');
  assert.equal(ui.requests.length, 1);
  assert.equal([...ui.timers.values()][0].delay, 14000);
  const hostile = '<img src=x onerror="alert(1)"><script>alert(1)</script>';
  ui.requests[0].resolve({ answer: hostile, source: 'local' });
  await submission;
  assert.equal(ui.answer.textContent, hostile);
  assert.equal(ui.result.hidden, false);
  assert.match(ui.source.textContent, /Réponse locale/);
  assert.equal(ui.pending.hidden, true);
  assertPageIdle(ui);
  const next = ui.form.fire('submit');
  ui.requests[1].resolve({ answer: 'Explication du modèle.', source: 'llm' });
  await next;
  assert.match(ui.source.textContent, /modèle local/);
  assertPageIdle(ui);
});

test('page restores controls after a service error and displays its message as text', async () => {
  const ui = pageHarness();
  const submission = ui.form.fire('submit');
  ui.requests[0].reject(new Error('<b>Service occupé</b>'));
  await submission;
  assert.equal(ui.error.hidden, false);
  assert.equal(ui.errorText.textContent, '<b>Service occupé</b>');
  assert.equal(ui.result.hidden, true);
  assertPageIdle(ui);
});

test('page cancellation aborts fetch and permits a new question', async () => {
  const ui = pageHarness();
  const submission = ui.form.fire('submit');
  await ui.cancel.fire('click');
  await submission;
  assert.equal(ui.requests[0].signal.aborted, true);
  assert.match(ui.pending.textContent, /annulée/);
  assertPageIdle(ui);
  const next = ui.form.fire('submit');
  assert.equal(ui.requests.length, 2);
  ui.requests[1].resolve({ source: 'local', answer: 'Nouvelle réponse' });
  await next;
  assert.equal(ui.answer.textContent, 'Nouvelle réponse');
});

test('page timeout aborts waiting, restores controls and allows resubmission', async () => {
  const ui = pageHarness();
  const submission = ui.form.fire('submit');
  [...ui.timers.values()][0].callback();
  await submission;
  assert.equal(ui.requests[0].signal.aborted, true);
  assert.match(ui.pending.textContent, /délai est dépassé/);
  assertPageIdle(ui);
  const next = ui.form.fire('submit');
  ui.requests[1].resolve({ source: 'local', answer: 'Bilan rapide' });
  await next;
  assert.equal(ui.answer.textContent, 'Bilan rapide');
  assertPageIdle(ui);
});

function widgetHarness() {
  const env = environment();
  const widget = new Element();
  widget.dataset = { endpoint: '/security/assistant-api.php', timeoutMs: '14000' };
  const launcher = new Element();
  const panel = new Element();
  panel.hidden = true;
  const close = new Element();
  const form = new Element();
  const question = new Element();
  const eventId = new Element();
  const selection = new Element();
  selection.hidden = true;
  const submit = new Element('Envoyer →');
  const cancel = new Element();
  cancel.hidden = true;
  const response = new Element();
  const metadata = new Element();
  for (const [selector, element] of [
    ['.assistant-launcher', launcher], ['.assistant-widget-panel', panel], ['.assistant-widget-close', close],
    ['.assistant-widget-form', form], ['.assistant-widget-response', response], ['.assistant-widget-meta', metadata],
  ]) widget.children.set(selector, element);
  for (const [selector, element] of [
    ['textarea[name="question"]', question], ['input[name="event_id"]', eventId],
    ['.assistant-widget-selection', selection], ['button[type="submit"]', submit], ['[data-assistant-cancel]', cancel],
  ]) form.children.set(selector, element);
  env.document.children.set('.assistant-widget', widget);
  const requests = installRequester(env);
  env.run('assistant-widget.js');
  return { ...env, widget, launcher, panel, close, form, question, eventId, selection, submit, cancel, response, metadata, requests };
}

test('widget selects an event outside the widget and passes only the event reference', async () => {
  const ui = widgetHarness();
  const trigger = new Element('Raw payload deliberately not trusted');
  trigger.matches = '.assistant-event-context';
  trigger.dataset = { eventId: 'event-42', payload: 'SECRET SQL PAYLOAD', ip: '192.0.2.1' };
  await ui.document.fire('click', { target: trigger });
  assert.equal(ui.eventId.value, 'event-42');
  assert.equal(ui.panel.hidden, false);
  assert.equal(ui.launcher.getAttribute('aria-expanded'), 'true');
  assert.equal(ui.selection.hidden, false);
  assert.doesNotMatch(ui.selection.textContent, /SECRET|192\.0\.2|Raw payload/);
  assert.match(ui.selection.textContent, /métadonnées/);
  assert.match(ui.question.value, /Explique cette alerte/);
  assert.doesNotMatch(ui.question.value, /SECRET|192\.0\.2|Raw payload/);
  assert.equal(ui.question.focused, true);
  const event = {};
  const submission = ui.form.fire('submit', event);
  assert.equal(event.defaultPrevented, true);
  await ui.form.fire('submit');
  assert.equal(ui.requests.length, 1);
  ui.requests[0].resolve({ answer: '<svg onload="alert(1)">', source: 'local' });
  await submission;
  assert.equal(ui.response.textContent, '<svg onload="alert(1)">');
  assert.match(ui.metadata.textContent, /Réponse locale/);
  assert.equal(ui.metadata.hidden, false);
  assert.equal(ui.eventId.value, '');
  assert.equal(ui.selection.hidden, true);
  assert.equal(ui.submit.disabled, false);
  assert.equal(ui.cancel.hidden, true);
  assert.equal(ui.timers.size, 0);
});

test('widget cancellation and timeout restore controls; successful LLM answers retain their source', async () => {
  const ui = widgetHarness();
  let submission = ui.form.fire('submit');
  await ui.cancel.fire('click');
  await submission;
  assert.match(ui.response.textContent, /annulée/);
  assert.equal(ui.requests[0].signal.aborted, true);
  assert.equal(ui.submit.disabled, false);
  assert.equal(ui.cancel.hidden, true);
  submission = ui.form.fire('submit');
  [...ui.timers.values()][0].callback();
  await submission;
  assert.match(ui.response.textContent, /délai est dépassé/);
  assert.equal(ui.submit.getAttribute('aria-busy'), null);
  assert.equal(ui.cancel.hidden, true);
  submission = ui.form.fire('submit');
  ui.requests[2].resolve({ answer: 'Analyse locale du modèle', source: 'llm' });
  await submission;
  assert.match(ui.metadata.textContent, /modèle local/);
  assert.equal(ui.response.classList.contains('is-error'), false);
  assert.equal(ui.submit.textContent, 'Envoyer →');
  assert.equal(ui.submit.disabled, false);
  assert.equal(ui.timers.size, 0);
});
