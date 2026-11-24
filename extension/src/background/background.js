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

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "COMPOSE_PRIVACY") {
    if (sender.id !== chrome.runtime.id || !sender.tab || !sender.url?.startsWith("https://mail.google.com/") ||
        typeof message.text !== "string" || message.text.length > 40000) return false;
    const preview = message.selected === undefined;
    fetch(BACKEND_URL + "/api/privacy-redact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: message.text, selected: message.selected, preview,
        findings_only: preview, context: "gmail_compose" }),
      signal: AbortSignal.timeout(5000)
    }).then(response => {
      if (!response.ok) throw new Error("Local privacy analysis unavailable");
      return response.json();
    }).then(data => sendResponse({ success: true, data: preview ? data : null }),
      () => sendResponse({ success: false }));
    return true;
  }

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

  // URL scan passthrough from content script
  if (message.type === "SCAN_URL") {
    fetch(`${BACKEND_URL}/api/scan-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: message.url })
    })
      .then((res) => res.json())
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});
