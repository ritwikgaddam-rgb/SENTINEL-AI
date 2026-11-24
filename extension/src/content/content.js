/**
 * Sentinel AI - Content Script (In-Page Email Guardian for Gmail)
 * Seamlessly integrates security badges, warning banners & privacy redactions directly into Gmail.
 */

(function () {
  console.log("[Sentinel AI] In-page Email Guardian active.");

  let userTheme = "cold"; // "cold" (#03094b) or "warm" (#541504)
  let userMode = "dark";
  let isEnabled = true;

  // Sync settings with chrome.storage if available
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["sentinel_theme", "sentinel_mode", "sentinel_gmailOverlay"], (data) => {
      if (data.sentinel_theme) userTheme = data.sentinel_theme;
      if (data.sentinel_mode) userMode = data.sentinel_mode;
      if (typeof data.sentinel_gmailOverlay === "boolean") isEnabled = data.sentinel_gmailOverlay;
    });

    chrome.storage.onChanged.addListener((changes) => {
      if (changes.sentinel_theme) userTheme = changes.sentinel_theme.newValue;
      if (changes.sentinel_mode) userMode = changes.sentinel_mode.newValue;
      if (changes.sentinel_gmailOverlay) isEnabled = changes.sentinel_gmailOverlay.newValue;
    });
  }

  function escaped(text) {
    return String(text ?? '').replace(/[&<>"']/g, character =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  }

  async function request(type, payload) {
    const result = await chrome.runtime.sendMessage({ type, payload });
    if (!result?.success) throw new Error('Local analysis unavailable');
    return result.data;
  }

  function getLogoSrc() {
    const filename = userTheme === "warm"
      ? "SentinelAILogoIcon-SentinelOnly(Orange).svg"
      : "SentinelAILogoIconOnlySentinel(Purple).svg";

    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
      return chrome.runtime.getURL(`logos/${filename}`);
    }
    return `logos/${filename}`;
  }

  /**
   * Scans an email message body with backend or client fallback
   */
  async function analyzeEmail(text, sender, subject, links) {
    try {
      return await request('SCAN_GMAIL_MESSAGE', { text: text.slice(0, 20000),
        sender: sender.slice(0, 500), subject: subject.slice(0, 500), links });
    } catch {
      return { risk_level: 'uncertain', assessment: 'Analysis unavailable',
        explanation: 'The local scanner could not check this message.', markers: [] };
    }
  }

  /**
   * Injects Sentinel AI Long Security Bar into opened Gmail messages
   */
  function inspectGmailMessages() {
    if (!isEnabled) return;

    // Target the primary message card container in Gmail exactly once
    const messageCards = document.querySelectorAll('.adn.ads');
    messageCards.forEach(async (card) => {
      if (card.getAttribute('data-sentinel-scanned') === 'true' || card.querySelector('.sentinel-gmail-bar-container')) {
        return;
      }
      card.setAttribute('data-sentinel-scanned', 'true');

      // Find message body
      const bodyEl = card.querySelector('.a3s, .ii.gt');
      const text = bodyEl ? bodyEl.innerText.trim() : "";
      if (!text) return;

      const senderEl = card.querySelector('.gD');
      const sender = senderEl ? (senderEl.getAttribute('email')
        ? `${senderEl.innerText} <${senderEl.getAttribute('email')}>` : senderEl.innerText) : '';
      const subject = document.querySelector('h2.hP')?.textContent || '';
      const links = [...bodyEl.querySelectorAll('a[href]')].slice(0, 50).map(anchor => ({
        url: anchor.getAttribute('href'), label: anchor.innerText.slice(0, 200),
      }));

      const analysis = await analyzeEmail(text, sender, subject, links);
      if (!card.isConnected || !isEnabled) return;
      const risk = analysis.risk_level === 'suspicious' ? 'suspicious' : 'uncertain';
      const title = escaped(analysis.assessment);
      const explanation = escaped(analysis.explanation);
      const markersHtml = analysis.markers.map(item => `
        <div class="sentinel-audit-marker ${item.severity === 'high' ? 'danger' : 'medium'}">
          <div class="sentinel-audit-marker-title">${escaped(item.title)}</div>
          <div class="sentinel-audit-marker-desc">${escaped(item.description)}</div>
        </div>
      `).join('');
      const barContainer = document.createElement('div');
      barContainer.className = `sentinel-gmail-bar-container theme-${userTheme === 'warm' ? 'warm' : 'cold'}`;
      barContainer.innerHTML = `
        <div class="sentinel-gmail-bar ${risk}">
          <div class="sentinel-bar-left">
            <img src="${getLogoSrc()}" class="sentinel-bar-logo" alt="Sentinel AI" />
            <span class="sentinel-bar-title">${title}</span>
            <span class="sentinel-bar-summary">${explanation}</span>
          </div>
          <button class="sentinel-bar-toggle-btn" type="button">Audit Details</button>
        </div>
        <div class="sentinel-gmail-audit-drawer" style="display: none;">
          <div class="sentinel-audit-markers-list">${markersHtml || explanation}</div>
        </div>`;

      // Drawer toggle handler
      const toggleBtn = barContainer.querySelector('.sentinel-bar-toggle-btn');
      const barEl = barContainer.querySelector('.sentinel-gmail-bar');
      const drawerEl = barContainer.querySelector('.sentinel-gmail-audit-drawer');
      const chevronEl = barContainer.querySelector('.sentinel-chevron-icon');

      const toggleDrawer = (e) => {
        e.stopPropagation();
        const isOpen = drawerEl.style.display !== 'none';
        drawerEl.style.display = isOpen ? 'none' : 'block';
        if (chevronEl) {
          chevronEl.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
        }
      };

      if (toggleBtn) toggleBtn.addEventListener('click', toggleDrawer);
      if (barEl) barEl.addEventListener('click', toggleDrawer);

      // Insert the long bar directly under the sender/date header (.gE.iv.gt)
      const headerRow = card.querySelector('.gE.iv.gt');
      if (headerRow && headerRow.nextSibling) {
        headerRow.parentNode.insertBefore(barContainer, headerRow.nextSibling);
      } else if (headerRow) {
        headerRow.parentNode.appendChild(barContainer);
      } else {
        card.insertBefore(barContainer, card.firstChild);
      }
    });
  }

  /**
   * Injects Privacy Guard into Gmail compose editors (Grammarly style)
   */
  function inspectGmailCompose() {
    if (!isEnabled) return;

    const composeEditors = document.querySelectorAll('.Am.Al.editable, div[aria-label*="Message Body"]');
    composeEditors.forEach((editor) => {
      const container = editor.closest('.M9') || editor.parentElement;
      if (!container || container.hasAttribute('data-sentinel-compose-attached')) return;
      container.setAttribute('data-sentinel-compose-attached', 'true');
      container.style.position = 'relative';

      const indicator = document.createElement('div');
      indicator.className = `sentinel-compose-indicator theme-${userTheme}`;
      indicator.title = 'Check this draft locally for private information';
      indicator.innerHTML = `<img src="${getLogoSrc()}" alt="Redact draft" style="height:16px; width:auto;" />`;
      container.appendChild(indicator);

      function snapshot() {
        const walker = document.createTreeWalker(editor, NodeFilter.SHOW_TEXT);
        const nodes = [];
        let text = '';
        let offset = 0;
        while (walker.nextNode() && offset < 40000 && nodes.length < 500) {
          const node = walker.currentNode;
          const chars = Array.from(node.data).slice(0, 40000 - offset);
          nodes.push({ node, chars, start: offset, end: offset + chars.length });
          text += chars.join('') + '\n';
          offset += chars.length + 1;
        }
        return { text: text.slice(0, 40000), nodes };
      }

      let timer, revision = 0;
      editor.addEventListener('input', () => {
        clearTimeout(timer);
        const current = ++revision;
        timer = setTimeout(async () => {
          if (!isEnabled) return;
          const { text } = snapshot();
          try {
            const result = text.trim() ? await request('SCAN_GMAIL_DRAFT', { text, preview: true }) : null;
            if (current !== revision) return;
            indicator.querySelector('.sentinel-compose-badge-num')?.remove();
            if (result?.total_redacted) {
              const badge = document.createElement('span');
              badge.className = 'sentinel-compose-badge-num';
              badge.textContent = String(result.total_redacted);
              indicator.appendChild(badge);
            }
          } catch { indicator.querySelector('.sentinel-compose-badge-num')?.remove(); }
        }, 450);
      });

      indicator.addEventListener('click', async event => {
        event.stopPropagation();
        if (!isEnabled) return;
        const draft = snapshot();
        if (!draft.text.trim()) return;
        try {
          const result = await request('SCAN_GMAIL_DRAFT', { text: draft.text, preview: true });
          const edits = result.redactions.flatMap(hit => {
            const item = draft.nodes.find(node => hit.start >= node.start && hit.end <= node.end);
            return item ? [{ hit, item }] : [];
          });
          const remaining = result.review.length + result.redactions.length - edits.length;
          if (!edits.length || !window.confirm(`Redact ${edits.length} validated match(es) in this draft? ${remaining} match(es) may need manual review.`)) return;
          if (snapshot().text !== draft.text) return;
          for (const { hit, item } of edits.reverse()) {
            const start = item.chars.slice(0, hit.start - item.start).join('').length;
            const length = item.chars.slice(hit.start - item.start, hit.end - item.start).join('').length;
            item.node.replaceData(start, length, hit.replacement);
          }
          editor.dispatchEvent(new Event('input', { bubbles: true }));
        } catch { window.alert('Local privacy analysis is unavailable.'); }
      });
    });
  }

  let scheduled = false;
  const observer = new MutationObserver(() => {
    if (scheduled) return;
    scheduled = true;
    setTimeout(() => {
      scheduled = false;
      inspectGmailMessages();
      inspectGmailCompose();
    }, 200);
  });

  observer.observe(document.body, { childList: true, subtree: true });

  setTimeout(() => {
    inspectGmailMessages();
    inspectGmailCompose();
  }, 1000);
})();
