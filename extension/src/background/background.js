/**
 * Sentinel AI - Background Service Worker (Manifest V3)
 * Handles lifecycle, tab monitoring, context menus, and toolbar icon switching.
 */

const BACKEND_URL = "http://127.0.0.1:8000";

// Icon variant path maps
const ICON_PATHS = {
  purple_shield: {
    16: "logos/purple_shield_16.png",
    32: "logos/purple_shield_32.png",
    48: "logos/purple_shield_48.png",
    128: "logos/purple_shield_128.png"
  },
  orange_shield: {
    16: "logos/orange_shield_16.png",
    32: "logos/orange_shield_32.png",
    48: "logos/orange_shield_48.png",
    128: "logos/orange_shield_128.png"
  },
  purple_minimal: {
    16: "logos/purple_minimal_16.png",
    32: "logos/purple_minimal_32.png",
    48: "logos/purple_minimal_48.png",
    128: "logos/purple_minimal_128.png"
  },
  orange_minimal: {
    16: "logos/orange_minimal_16.png",
    32: "logos/orange_minimal_32.png",
    48: "logos/orange_minimal_48.png",
    128: "logos/orange_minimal_128.png"
  },
  purple_emblem: {
    16: "logos/purple_emblem_16.png",
    32: "logos/purple_emblem_32.png",
    48: "logos/purple_emblem_48.png",
    128: "logos/purple_emblem_128.png"
  },
  orange_emblem: {
    16: "logos/orange_emblem_16.png",
    32: "logos/orange_emblem_32.png",
    48: "logos/orange_emblem_48.png",
    128: "logos/orange_emblem_128.png"
  }
};

function applyIcon(variantId) {
  const paths = ICON_PATHS[variantId];
  if (!paths) {
    console.warn("[Sentinel AI] Unknown toolbar icon variant:", variantId);
    return;
  }
  chrome.action.setIcon({ path: paths }, () => {
    if (chrome.runtime.lastError) {
      console.warn("[Sentinel AI] setIcon error:", chrome.runtime.lastError.message);
    }
  });
}

function restoreSavedIcon() {
  chrome.storage.local.get(["sentinel_toolbar_icon"], (result) => {
    if (chrome.runtime.lastError) {
      console.error("[Sentinel AI] Failed to restore toolbar icon:", chrome.runtime.lastError.message);
      return;
    }
    if (result.sentinel_toolbar_icon) {
      applyIcon(result.sentinel_toolbar_icon);
    }
  });
}

chrome.runtime.onStartup.addListener(restoreSavedIcon);

// Initialize default settings on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(
    ["sentinel_theme", "sentinel_mode", "sentinel_urlShield", "sentinel_gmailOverlay", "sentinel_toolbar_icon"],
    (result) => {
      const defaults = {};
      if (!result.sentinel_theme) defaults.sentinel_theme = "cold";
      if (!result.sentinel_mode) defaults.sentinel_mode = "dark";
      if (typeof result.sentinel_urlShield === "undefined") defaults.sentinel_urlShield = true;
      if (typeof result.sentinel_gmailOverlay === "undefined") defaults.sentinel_gmailOverlay = true;
      if (!result.sentinel_toolbar_icon) defaults.sentinel_toolbar_icon = "purple_minimal";

      chrome.storage.local.set(defaults, () => {
        // Apply the default icon on first install
        applyIcon(result.sentinel_toolbar_icon || "purple_minimal");
      });
    }
  );

  // Cleanly remove any existing menus before creating to prevent duplicate ID errors
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "sentinel_scan_selection",
      title: "Inspect Selected Text with Sentinel AI",
      contexts: ["selection"]
    });
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== 'sentinel_scan_selection' || !info.selectionText || tab?.id == null) return;
  const tabId = tab.id;
  fetch(BACKEND_URL + '/api/scan-email', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, redirect: 'error',
    body: JSON.stringify({ text: info.selectionText.slice(0, 20000) }),
  }).then(async response => {
    const assessment = response.ok ? (await response.json()).risk_level : 'unavailable';
    await chrome.action.setBadgeText({ tabId, text: assessment === 'suspicious' ? '!' : '?' });
  }).catch(() => chrome.action.setBadgeText({ tabId, text: '?' }).catch(() => {}));
});

chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status === 'loading') chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Toolbar icon switching from the Settings popup
  if (message.type === "SET_TOOLBAR_ICON") {
    const variantId = message.variantId;
    const paths = ICON_PATHS[variantId];
    if (!paths) {
      sendResponse({ success: false, error: "Unknown toolbar icon variant." });
      return false;
    }

    // Apply via chrome.action.setIcon (MV3)
    chrome.action.setIcon({ path: paths }, () => {
      if (chrome.runtime.lastError) {
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
        return;
      }

      chrome.storage.local.set({ sentinel_toolbar_icon: variantId }, () => {
        if (chrome.runtime.lastError) {
          sendResponse({ success: false, error: chrome.runtime.lastError.message });
          return;
        }
        sendResponse({ success: true });
      });
    });
    return true; // keep sendResponse alive for async
  }

  let path, body;
  const tabId = sender.tab?.id;
  if (message.type === "PAGE_WATCH_STOPPED" && tabId != null && sender.frameId === 0) {
    chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
    return false;
  }
  if (message.type === "PAGE_OBSERVATIONS" && tabId != null && sender.frameId === 0) {
    const origin = new URL(sender.url).origin;
    if (origin !== message.origin || !/^https?:/.test(origin)) return false;
    path = '/api/scan-page';
    body = { url: origin, observations: message.observations, preview: true };
  } else if (message.type === "SCAN_URL") {
    path = '/api/scan-url';
    body = { url: message.url };
  } else if (["SCAN_GMAIL_MESSAGE", "SCAN_GMAIL_DRAFT"].includes(message.type) &&
      sender.url?.startsWith('https://mail.google.com/') && sender.frameId === 0) {
    path = message.type === 'SCAN_GMAIL_DRAFT' ? '/api/privacy-redact' : '/api/scan-email';
    body = { ...message.payload, collect_sample: false, context: 'gmail_compose' };
  }
  if (!path) return false;
  fetch(BACKEND_URL + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    redirect: 'error', body: JSON.stringify(body),
  }).then(async response => {
    if (!response.ok) throw new Error('Local assessment failed.');
    const data = await response.json();
    if (message.type === "PAGE_OBSERVATIONS") {
      await chrome.action.setBadgeText({ tabId, text: data.risk_level === 'suspicious' ? '!' : '' });
      if (data.risk_level === 'suspicious') await chrome.action.setBadgeBackgroundColor({ tabId, color: '#B42318' });
    }
    sendResponse({ success: true, data });
  }).catch(() => sendResponse({ success: false, error: 'Local analysis unavailable.' }));
  return true;
});
