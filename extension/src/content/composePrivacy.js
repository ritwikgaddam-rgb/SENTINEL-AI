// Gmail drafts stay in the editor and the loopback privacy service.
const HISTORICAL = '.gmail_quote, .gmail_signature, .gmail_extra, [data-smartmail="gmail_signature"], blockquote';
const BLOCK = 'div,p,li,ul,ol,table,tr,td,blockquote,pre,section,article';
const LIMIT = 40000;

function snapshot(editor, includeHistory) {
  const parts = [];
  const nodes = [];
  let length = 0;
  let lastBlock = null;
  let oversized = false;

  function append(text) {
    length += text.length;
    oversized = length > LIMIT;
    if (!oversized) parts.push(text);
  }

  function lineBreak() {
    if (parts.length && !parts.at(-1).endsWith('\n')) append('\n');
  }

  function visit(node) {
    if (oversized) return;
    if (node.nodeType === Node.TEXT_NODE && node.data) {
      const block = node.parentElement.closest(BLOCK);
      if (lastBlock && block !== lastBlock) lineBreak();
      lastBlock = block;
      const start = length;
      append(node.data);
      if (!oversized) nodes.push({ node, start, end: length });
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      if (!includeHistory && node.matches(HISTORICAL)) {
        // Keep identifiers on the two sides of excluded text separate.
        if (parts.length) append('\n\n');
      } else if (node.matches('br')) {
        append('\n');
      } else if (!node.matches('script,style,[hidden],[contenteditable="false"]')) {
        for (const child of node.childNodes) visit(child);
      }
    }
  }
  for (const child of editor.childNodes) visit(child);
  return { text: parts.join(''), nodes, oversized };
}

function planEdits(draft, findings) {
  const offsets = [0];
  for (const character of draft.text) offsets.push(offsets.at(-1) + character.length);
  const changes = new Map();
  const links = new Map();
  for (const finding of [...findings].sort((a, b) => b.start - a.start)) {
    const start = offsets[finding.start];
    const end = offsets[finding.end];
    if (start === undefined || end === undefined || start >= end) return null;
    const matched = draft.nodes.filter(entry => entry.start < end && entry.end > start);
    if (!matched.length) return null;
    const value = draft.text.slice(start, end);
    matched.forEach(({ node, start: nodeStart, end: nodeEnd }, index) => {
      if (!changes.has(node)) changes.set(node, { before: node.data, after: node.data });
      const edit = changes.get(node);
      edit.after = edit.after.slice(0, Math.max(start, nodeStart) - nodeStart)
        + (index === 0 ? finding.replacement : '')
        + edit.after.slice(Math.min(end, nodeEnd) - nodeStart);
      const anchor = node.parentElement.closest('a[href]');
      if (anchor && !links.has(anchor)) {
        const href = anchor.getAttribute('href');
        let decoded = href;
        try { decoded = decodeURIComponent(href); } catch { /* Keep the literal URL for comparison. */ }
        if (decoded.toLowerCase().includes(value.toLowerCase())) links.set(anchor, href);
      }
    });
  }
  return { changes, links };
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function privacyRequest(text, selected) {
  if (!chrome.runtime?.id) return Promise.reject(new Error('Extension unavailable'));
  return chrome.runtime.sendMessage({ type: 'COMPOSE_PRIVACY', text, selected }).then(result => {
    if (!result?.success) throw new Error('Local privacy analysis unavailable');
    return result.data;
  });
}

function automatic(match) {
  return match.ambiguous === false && match.confidence === 'high';
}

export function attachComposePrivacy(editor, container, theme, logo) {
  const indicator = element('div', 'sentinel-compose-indicator theme-' + theme);
  const trigger = element('img');
  trigger.src = logo;
  trigger.style.cssText = 'height:16px;width:auto';
  trigger.tabIndex = 0;
  trigger.setAttribute('role', 'button');
  trigger.setAttribute('aria-label', 'Sentinel AI Privacy Guard');
  trigger.setAttribute('aria-expanded', 'false');
  indicator.title = 'Sentinel AI Privacy Guard';
  const shell = element('div', 'sentinel-gmail-bar-container theme-' + theme + ' sentinel-compose-panel');
  shell.hidden = true;
  const panel = element('section', 'sentinel-gmail-audit-drawer');
  panel.setAttribute('aria-label', 'Draft redaction');
  shell.append(panel);
  indicator.append(trigger, shell);
  container.style.position = 'relative';
  container.append(indicator);

  let includedHistory = false;
  let findings = [];
  let source = null;
  let selected = new Set();
  let revision = 0;
  let timer;
  let undo = null;
  let status = 'Checking draft…';

  function action(label, handler, disabled = false) {
    const button = element('button', 'sentinel-bar-toggle-btn', label);
    button.type = 'button';
    button.disabled = disabled;
    button.addEventListener('click', handler);
    return button;
  }

  function toggle(label, checked, onChange) {
    const wrapper = element('label', 'sentinel-compose-choice');
    const checkbox = element('input');
    checkbox.type = 'checkbox';
    checkbox.checked = checked;
    checkbox.addEventListener('change', () => onChange(checkbox.checked));
    wrapper.append(checkbox, document.createTextNode(label));
    return { wrapper, checkbox };
  }

  function render() {
    let badge = indicator.querySelector('.sentinel-compose-badge-num');
    if (findings.length) {
      if (!badge) {
        badge = element('span', 'sentinel-compose-badge-num');
        indicator.append(badge);
      }
      badge.textContent = findings.length;
    } else {
      badge?.remove();
    }
    if (shell.hidden) return;
    const heading = element('div', 'sentinel-audit-header');
    heading.append(element('div', 'sentinel-audit-title', 'Draft Privacy Guard'),
      action('Collapse', () => setOpen(false)));
    const history = toggle('Include quotes and signature', includedHistory, value => {
      includedHistory = value;
      queue();
    });
    const list = element('div', 'sentinel-compose-findings');
    const controls = element('div', 'sentinel-compose-actions');
    const choices = [];
    const groups = new Map();
    for (const match of findings) {
      if (!groups.has(match.category)) groups.set(match.category, []);
      groups.get(match.category).push(match);
    }

    function update() {
      for (const { input, ids } of choices) {
        const count = ids.filter(id => selected.has(id)).length;
        input.checked = count === ids.length;
        input.indeterminate = count > 0 && count < ids.length;
      }
      redactSelected.disabled = !source || selected.size === 0;
      all.disabled = !source || !findings.some(item => automatic(item) || selected.has(item.id));
    }

    function select(ids, enabled) {
      for (const id of ids) {
        if (enabled) selected.add(id);
        else selected.delete(id);
      }
      update();
    }

    for (const group of groups.values()) {
      const card = element('div', 'sentinel-audit-marker');
      const ids = group.map(item => item.id);
      const name = group[0].replacement.slice(1, -1);
      const category = toggle(name + ' (' + group.length + ')', false, value => select(ids, value));
      category.wrapper.classList.add('sentinel-audit-marker-title');
      choices.push({ input: category.checkbox, ids });
      card.append(category.wrapper);
      group.forEach((match, index) => {
        const needsReview = match.validation === 'invalid_format_or_checksum' ? ' · Invalid format or checksum' :
          !automatic(match) ? ' · Review' : '';
        const row = toggle('#' + (index + 1) + ' ' + match.masked_preview + needsReview,
          selected.has(match.id), value => select([match.id], value));
        choices.push({ input: row.checkbox, ids: [match.id] });
        card.append(row.wrapper);
      });
      list.append(card);
    }
    const redactSelected = action('Redact selected', () => redact(findings.filter(item => selected.has(item.id))));
    const allIds = findings.map(item => item.id);
    const all = action('Redact all', () => redact(findings.filter(item => automatic(item) || selected.has(item.id))));
    all.title = 'Redacts automatic matches and any review items you selected';
    controls.append(action('Select all', () => select(allIds, true), !findings.length),
      action('Deselect all', () => select(allIds, false), !findings.length), redactSelected, all,
      action('Undo', restore, !undo));
    panel.replaceChildren(heading, history.wrapper);
    if (status) {
      const message = element('p', 'sentinel-audit-marker-desc', status);
      message.setAttribute('role', 'status');
      panel.append(message);
    }
    panel.append(list, controls);
    update();
  }

  function setOpen(open) {
    shell.hidden = !open;
    trigger.setAttribute('aria-expanded', String(open));
    indicator.title = open ? '' : 'Sentinel AI Privacy Guard';
    if (open) render();
    else trigger.focus();
  }

  function queue() {
    if (!editor.isConnected) return;
    const request = ++revision;
    clearTimeout(timer);
    source = null;
    findings = [];
    selected = new Set();
    status = 'Checking draft…';
    render();
    timer = setTimeout(async () => {
      const draft = snapshot(editor, includedHistory);
      status = draft.oversized ? 'Draft is too long for local analysis.' : 'No sensitive information detected.';
      if (draft.oversized || !draft.text.trim()) {
        render();
        return;
      }
      try {
        const result = await privacyRequest(draft.text);
        if (request !== revision || !editor.isConnected) return;
        if (draft.text !== snapshot(editor, includedHistory).text) {
          queue();
          return;
        }
        source = draft.text;
        findings = result.findings;
        selected = new Set(findings.filter(automatic).map(item => item.id));
        status = findings.length ? '' : 'No sensitive information detected.';
      } catch {
        if (request !== revision || !editor.isConnected) return;
        status = 'Local privacy analysis unavailable.';
      }
      render();
    }, 220);
  }

  function redact(items) {
    const draft = snapshot(editor, includedHistory);
    if (source === null || draft.oversized || source !== draft.text) {
      queue();
      return;
    }
    if (!items.length) return;
    const edits = planEdits(draft, items);
    if (!edits) {
      queue();
      return;
    }
    for (const [node, change] of edits.changes) node.data = change.after;
    for (const anchor of edits.links.keys()) anchor.removeAttribute('href');
    undo = edits;
    editor.dispatchEvent(new Event('input', { bubbles: true }));
    // Re-run selection in the local service for a count-only audit.
    privacyRequest(draft.text, items.map(item => item.id)).catch(() => {});
  }

  function restore() {
    if (!undo) return;
    const edits = undo;
    undo = null;
    if ([...edits.changes].some(([node, change]) => !editor.contains(node) || node.data !== change.after)
      || [...edits.links.keys()].some(anchor => !editor.contains(anchor) || anchor.hasAttribute('href'))) {
      render();
      return;
    }
    for (const [node, change] of edits.changes) node.data = change.before;
    for (const [anchor, href] of edits.links) anchor.setAttribute('href', href);
    editor.dispatchEvent(new Event('input', { bubbles: true }));
  }

  indicator.addEventListener('click', event => {
    event.stopPropagation();
    if (!event.composedPath().includes(shell)) setOpen(shell.hidden);
  });
  indicator.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !shell.hidden) setOpen(false);
    if (event.target === trigger && ['Enter', ' '].includes(event.key)) {
      event.preventDefault();
      setOpen(shell.hidden);
    }
  });
  editor.addEventListener('input', queue);
  new MutationObserver(queue).observe(editor, { childList: true, characterData: true, subtree: true });
  queue();
}
