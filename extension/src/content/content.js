/**
 * Sentinel AI - Content Script (In-Page Email Guardian for Gmail)
 * Seamlessly integrates security badges & privacy redactions directly into Gmail.
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
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

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
    } catch (e) {
      // Local fallback
    }

    const textLower = text.toLowerCase();
    const hasUrgency = /urgent|suspended|deactivated|password|verify|immediately|within \d+ hours/.test(textLower);
    const aadhaarMatches = text.match(aadhaarRegex) || [];
    const phoneMatches = text.match(phoneRegex) || [];

    const markers = [];
    if (hasUrgency) {
      markers.append({
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
   * Injects Sentinel AI Badge into opened Gmail message headers
   */
  function inspectGmailMessages() {
    if (!isEnabled) return;

    // Selector for Gmail email message containers
    const messageHeaders = document.querySelectorAll('.gE.iv.gt, .adn.ads');
    messageHeaders.forEach(async (header) => {
      if (header.hasAttribute('data-sentinel-scanned')) return;
      header.setAttribute('data-sentinel-scanned', 'true');

      // Find message body
      const emailContainer = header.closest('.gs') || header.parentElement;
      const bodyEl = emailContainer ? emailContainer.querySelector('.a3s, .ii.gt') : null;
      const text = bodyEl ? bodyEl.innerText.trim() : "";
      if (!text || text.length < 15) return;

      const senderEl = header.querySelector('.gD');
      const sender = senderEl ? (senderEl.getAttribute('email') || senderEl.innerText) : "";

      // Analyze
      const analysis = await analyzeEmail(text, sender);
      const risk = analysis.risk_level || "safe";

      // Create Badge
      const badge = document.createElement('div');
      badge.className = `sentinel-gmail-badge theme-${userTheme} ${risk}`;
      badge.innerHTML = `
        <img src="${getLogoSrc()}" class="sentinel-badge-logo" alt="Sentinel AI" />
        <span>${risk === 'safe' ? 'Verified Safe' : risk === 'suspicious' ? 'Caution' : 'Threat Detected'}</span>
      `;

      // Create Expandable Popover
      const popover = document.createElement('div');
      popover.className = `sentinel-gmail-popover theme-${userTheme}`;
      popover.style.display = 'none';

      let markersHtml = '';
      if (analysis.markers && analysis.markers.length > 0) {
        markersHtml = analysis.markers.map(m => `
          <div class="sentinel-popover-marker ${m.severity || 'medium'}">
            <div class="sentinel-popover-marker-title">${m.title}</div>
            <div class="sentinel-popover-marker-desc">${m.description}</div>
          </div>
        `).join('');
      } else {
        markersHtml = `
          <div class="sentinel-popover-marker safe">
            <div class="sentinel-popover-marker-title">Clean Audit</div>
            <div class="sentinel-popover-marker-desc">No deceptive heuristics or privacy violations detected.</div>
          </div>
        `;
      }

      popover.innerHTML = `
        <div class="sentinel-popover-header">
          <div class="sentinel-popover-title">
            <img src="${getLogoSrc()}" style="height:14px; width:auto;" />
            <span>Sentinel AI Security Audit</span>
          </div>
          <span style="font-size:11px; opacity:0.8;">${analysis.safety_score}% Safe</span>
        </div>
        <div>${markersHtml}</div>
        ${analysis.private_items_count > 0 ? `
          <div style="margin-top:8px; padding-top:6px; border-top:1px solid rgba(255,255,255,0.1); font-size:11px; display:flex; justify-content:space-between; align-items:center;">
            <span>🛡️ ${analysis.private_items_count} Identity points exposed</span>
          </div>
        ` : ''}
      `;

      badge.addEventListener('click', (e) => {
        e.stopPropagation();
        popover.style.display = popover.style.display === 'none' ? 'block' : 'none';
      });

      // Close on clicking outside
      document.addEventListener('click', (e) => {
        if (!badge.contains(e.target) && !popover.contains(e.target)) {
          popover.style.display = 'none';
        }
      });

      const wrapper = document.createElement('div');
      wrapper.style.position = 'relative';
      wrapper.style.display = 'inline-block';
      wrapper.appendChild(badge);
      wrapper.appendChild(popover);

      // Attach next to subject / sender area
      const dateArea = header.querySelector('.g3') || header.querySelector('.gK') || header;
      dateArea.parentNode.insertBefore(wrapper, dateArea);
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

      // Listen for typing events to check for Aadhaar or Phone numbers
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

      // Clicking indicator offers 1-click automatic redaction
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

  // Run observer continuously
  const observer = new MutationObserver(() => {
    inspectGmailMessages();
    inspectGmailCompose();
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial pass
  setTimeout(() => {
    inspectGmailMessages();
    inspectGmailCompose();
  }, 1000);
})();
