import { attachComposePrivacy } from "./composePrivacy";

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
      const result = await chrome.runtime.sendMessage({type: 'SCREEN', kind: 'email', input: {text, sender, subject, links}});
      if (result) return result;
    } catch { /* Extension was unloaded while the Gmail tab was open. */ }
    return { risk_level: "unknown", assessment: "Analysis unavailable", safety_score: null, markers: [] };
  }

  // The legacy API already encodes entities. Protect HTML text slots from raw
  // tags returned by an older or incompatible local service as well.
  const markerText = value => typeof value === 'string'
    ? value.replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    : '';

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


      // Find message body
      const bodyEl = card.querySelector('.a3s, .ii.gt');
      const text = bodyEl ? bodyEl.innerText.trim() : "";
      if (!text) return;
      card.setAttribute('data-sentinel-scanned', 'true');

      const senderEl = card.querySelector('.gD');
      const address = senderEl?.getAttribute('email');
      const sender = address ? (senderEl.textContent.trim() + ' <' + address + '>') : (senderEl?.textContent || '');

      // Analyze
      const subject = (document.querySelector('h2.hP')?.textContent || '').slice(0, 500);
      const links = [...bodyEl.querySelectorAll('a[href]')].slice(0, 40).map(link => ({
        url: link.getAttribute('href'), label: link.textContent.slice(0, 200)
      }));
      const analysis = await analyzeEmail(text.slice(0, 20000), sender.slice(0, 500), subject, links);
      const risk = ["safe", "suspicious", "danger"].includes(analysis.risk_level) ? analysis.risk_level : "unknown";
      const score = Number.isFinite(analysis.safety_score) && analysis.safety_score >= 0 && analysis.safety_score <= 100
        ? analysis.safety_score + "% Safe" : "Score unavailable";
      const markers = Array.isArray(analysis.markers)
        ? analysis.markers.filter(item => item && typeof item.description === 'string').slice(0, 32)
        : [];
      const privateCount = Number.isSafeInteger(analysis.private_items_count) ? analysis.private_items_count : 0;
      const isSafe = risk === "safe";
      const isSuspicious = risk === "suspicious";

      // If suspicious or danger, inject prominent warning banner directly inside email body container
      if ((risk === "danger" || risk === "suspicious") && bodyEl && !bodyEl.querySelector('.sentinel-threat-banner')) {
        const banner = document.createElement('div');
        banner.className = `sentinel-threat-banner ${risk}`;
        const mainWarning = markers.length ? markerText(markers[0].description) : "This email exhibits deceptive phishing heuristics. Proceed with caution.";
        banner.innerHTML = `
          <div class="sentinel-threat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18" style="display:block;">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div class="sentinel-threat-content">
            <div class="sentinel-threat-heading">
              <span>Sentinel AI Security Alert (${score})</span>
            </div>
            <div class="sentinel-threat-details">${mainWarning}</div>
          </div>
        `;
        bodyEl.insertBefore(banner, bodyEl.firstChild);
      }

      // Build the Long Security Bar Container
      const barContainer = document.createElement('div');
      barContainer.className = `sentinel-gmail-bar-container theme-${userTheme}`;

      const statusTitle = isSafe ? "No clear indicators" : isSuspicious ? "Security Caution" : risk === "danger" ? "Threat Flagged" : "No score";
      const statusSummary = isSafe
        ? "Review unexpected requests independently. Privacy findings are shown separately."
        : (markers.length ? markerText(markers[0].description) : "A local assessment could not be completed.");

      let markersHtml = '';
      if (markers.length > 0) {
        markersHtml = markers.map(m => `
          <div class="sentinel-audit-marker ${['danger', 'high', 'medium', 'low', 'safe'].includes(m.severity) ? m.severity : 'medium'}">
            <div class="sentinel-audit-marker-title">${markerText(m.title)}</div>
            <div class="sentinel-audit-marker-desc">${markerText(m.description)}</div>
          </div>
        `).join('');
      } else {
        markersHtml = `
          <div class="sentinel-audit-marker safe">
            <div class="sentinel-audit-marker-title">No Direct Phishing Flags Found</div>
            <div class="sentinel-audit-marker-desc">No urgent social engineering patterns, direct credential demands, or rogue external links were detected.</div>
          </div>
        `;
      }

      barContainer.innerHTML = `
        <div class="sentinel-gmail-bar ${risk}">
          <div class="sentinel-bar-left">
            <img src="${getLogoSrc()}" class="sentinel-bar-logo" alt="Sentinel AI" />
            <span class="sentinel-bar-title">${statusTitle}</span>
            <span class="sentinel-bar-sep">•</span>
            <span class="sentinel-bar-summary">${statusSummary}</span>
          </div>
          <div class="sentinel-bar-right">
            <span class="sentinel-bar-score">${score}</span>
            <button class="sentinel-bar-toggle-btn" type="button">
              <span>Audit Details</span>
              <svg class="sentinel-chevron-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12">
                <polyline points="6 9 12 15 18 9"/>
              </svg>
            </button>
          </div>
        </div>

        <div class="sentinel-gmail-audit-drawer" style="display: none;">
          <div class="sentinel-audit-header">
            <div class="sentinel-audit-title">
              <img src="${getLogoSrc()}" style="height:14px; width:auto;" />
              <span>Sentinel AI Security Audit</span>
            </div>
            <span class="sentinel-audit-score">${score}</span>
          </div>
          <div class="sentinel-audit-markers-list">
            ${markersHtml}
          </div>
          ${privateCount > 0 ? `
            <div class="sentinel-audit-privacy-footer">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>${privateCount} Sensitive identity point(s) detected</span>
            </div>
          ` : ''}
        </div>
      `;

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
  const attachedEditors = new WeakSet();
  function inspectGmailCompose() {
    if (!isEnabled) return;

    document.querySelectorAll('.Am.Al.editable, [contenteditable="true"][aria-label*="Message Body"]').forEach(editor => {
      if (attachedEditors.has(editor) || editor.closest('.gmail_quote, blockquote')) return;
      const container = editor.closest('.M9') || editor.parentElement;
      if (!container) return;
      attachedEditors.add(editor);
      attachComposePrivacy(editor, container, userTheme, getLogoSrc());
    });
  }

  const observer = new MutationObserver(() => {
    inspectGmailMessages();
    inspectGmailCompose();
  });

  observer.observe(document.body, { childList: true, subtree: true });

  setTimeout(() => {
    inspectGmailMessages();
    inspectGmailCompose();
  }, 1000);
})();
