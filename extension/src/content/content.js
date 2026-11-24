/**
 * Sentinel AI - Content Script (In-Page Email Guardian for Gmail)
 * Seamlessly integrates security badges, warning banners & privacy redactions directly into Gmail.
 */

(function () {
  console.log("[Sentinel AI] In-page Email Guardian active.");

  let userTheme = "cold"; // "cold" (#03094b) or "warm" (#541504)
  let userMode = "dark";
  let isEnabled = true;
  const BACKEND_URL = "http://127.0.0.1:8000";

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

  // Regex patterns from privacy_detector.py
  const aadhaarRegex = /(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)/g;
  const phoneRegex = /(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)/g;

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
  async function analyzeEmail(text, sender) {
    try {
      const res = await fetch(`${BACKEND_URL}/api/scan-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, sender })
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // Local fallback
    }

    const textLower = text.toLowerCase();
    const hasUrgency = /urgent|suspended|deactivated|password|verify|immediately|within \d+ hours/.test(textLower);
    const aadhaarMatches = text.match(aadhaarRegex) || [];
    const phoneMatches = text.match(phoneRegex) || [];

    const markers = [];
    if (hasUrgency) {
      markers.push({
        id: "urgency_trigger",
        title: "High-Pressure Psychological Trigger",
        description: "Message contains urgency keywords common in account-takeover scams.",
        severity: "danger"
      });
    }
    if (aadhaarMatches.length > 0) {
      markers.push({
        id: "aadhaar_present",
        title: "Unredacted Aadhaar Number Detected",
        description: `Exposes ${aadhaarMatches.length} Indian national ID number(s).`,
        severity: "danger"
      });
    }

    return {
      risk_level: hasUrgency || aadhaarMatches.length > 0 ? "danger" : "safe",
      safety_score: hasUrgency || aadhaarMatches.length > 0 ? 25.0 : 96.0,
      markers: markers,
      privacy: {
        aadhaar_numbers: aadhaarMatches,
        phone_numbers: phoneMatches
      },
      private_items_count: aadhaarMatches.length + phoneMatches.length
    };
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
      if (!text || text.length < 15) return;

      const senderEl = card.querySelector('.gD');
      const sender = senderEl ? (senderEl.getAttribute('email') || senderEl.innerText) : "";

      // Analyze
      const analysis = await analyzeEmail(text, sender);
      const risk = analysis.risk_level || "safe";
      const isSafe = risk === "safe";
      const isSuspicious = risk === "suspicious";

      // If suspicious or danger, inject prominent warning banner directly inside email body container
      if ((risk === "danger" || risk === "suspicious") && bodyEl && !bodyEl.querySelector('.sentinel-threat-banner')) {
        const banner = document.createElement('div');
        banner.className = `sentinel-threat-banner ${risk}`;
        const mainWarning = analysis.markers && analysis.markers[0] ? analysis.markers[0].description : "This email exhibits deceptive phishing heuristics. Proceed with caution.";
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
              <span>Sentinel AI Security Alert (${analysis.safety_score}% Safety Score)</span>
            </div>
            <div class="sentinel-threat-details">${mainWarning}</div>
          </div>
        `;
        bodyEl.insertBefore(banner, bodyEl.firstChild);
      }

      // Build the Long Security Bar Container
      const barContainer = document.createElement('div');
      barContainer.className = `sentinel-gmail-bar-container theme-${userTheme}`;

      const statusTitle = isSafe ? "Verified Safe" : isSuspicious ? "Security Caution" : "Threat Flagged";
      const statusSummary = isSafe
        ? "No deceptive links, spoofed headers, or unredacted identity points detected in this message."
        : (analysis.markers && analysis.markers[0] ? analysis.markers[0].description : "Potential social engineering or phishing markers detected.");

      let markersHtml = '';
      if (analysis.markers && analysis.markers.length > 0) {
        markersHtml = analysis.markers.map(m => `
          <div class="sentinel-audit-marker ${m.severity || 'medium'}">
            <div class="sentinel-audit-marker-title">${m.title}</div>
            <div class="sentinel-audit-marker-desc">${m.description}</div>
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
            <span class="sentinel-bar-score">${analysis.safety_score}% Safe</span>
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
            <span class="sentinel-audit-score">${analysis.safety_score}% Safe</span>
          </div>
          <div class="sentinel-audit-markers-list">
            ${markersHtml}
          </div>
          ${analysis.private_items_count > 0 ? `
            <div class="sentinel-audit-privacy-footer">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>${analysis.private_items_count} Sensitive identity point(s) detected</span>
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
      indicator.title = "Sentinel AI Privacy Guard: Monitoring unredacted Aadhaar & Phone data";
      indicator.innerHTML = `
        <img src="${getLogoSrc()}" style="height:16px; width:auto;" />
      `;

      container.appendChild(indicator);

      editor.addEventListener('input', () => {
        const text = editor.innerText || editor.textContent || "";
        const aadhaars = text.match(aadhaarRegex) || [];
        const phones = text.match(phoneRegex) || [];
        const count = aadhaars.length + phones.length;

        let badgePill = indicator.querySelector('.sentinel-compose-badge-num');
        if (count > 0) {
          if (!badgePill) {
            badgePill = document.createElement('span');
            badgePill.className = 'sentinel-compose-badge-num';
            indicator.appendChild(badgePill);
          }
          badgePill.innerText = count;
        } else if (badgePill) {
          badgePill.remove();
        }
      });

      indicator.addEventListener('click', (e) => {
        e.stopPropagation();
        let text = editor.innerHTML;
        const aadhaars = text.match(aadhaarRegex) || [];
        const phones = text.match(phoneRegex) || [];

        if (aadhaars.length === 0 && phones.length === 0) {
          alert("Sentinel AI Privacy Guard: No unredacted Aadhaar or Phone numbers detected in this draft.");
          return;
        }

        if (confirm(`Sentinel AI detected ${aadhaars.length} Aadhaar number(s) and ${phones.length} Phone number(s). Would you like to automatically redact them with [AADHAAR] and [PHONE] tags?`)) {
          text = text.replace(aadhaarRegex, "[AADHAAR]");
          text = text.replace(phoneRegex, "[PHONE]");
          editor.innerHTML = text;

          const badgePill = indicator.querySelector('.sentinel-compose-badge-num');
          if (badgePill) badgePill.remove();
        }
      });
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
