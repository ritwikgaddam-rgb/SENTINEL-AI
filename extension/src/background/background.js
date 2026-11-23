/**
 * Sentinel AI - Background Service Worker (Manifest V3)
 * Handles lifecycle, tab monitoring, context menus, and toolbar icon switching.
 */

const BACKEND_URL = "http://127.0.0.1:8000";

// Restore saved toolbar icon on every service-worker startup
chrome.storage.local.get(["sentinel_toolbar_icon"], (result) => {
  if (result.sentinel_toolbar_icon) {
    applyIcon(result.sentinel_toolbar_icon);
  }
});

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
  }
};

function applyIcon(variantId) {
  const paths = ICON_PATHS[variantId];
  if (!paths) return;
  chrome.action.setIcon({ path: paths }, () => {
    if (chrome.runtime.lastError) {
      console.warn("[Sentinel AI] setIcon error:", chrome.runtime.lastError.message);
    }
  });
}

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
  if (info.menuItemId === "sentinel_scan_selection" && info.selectionText) {
    console.log("[Sentinel AI] Selected text for audit:", info.selectionText.substring(0, 50));
  }
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Toolbar icon switching from the Settings popup
  if (message.type === "SET_TOOLBAR_ICON") {
    const variantId = Object.keys(ICON_PATHS).find(k =>
      JSON.stringify(ICON_PATHS[k]) === JSON.stringify(message.paths)
    ) || Object.keys(ICON_PATHS)[0];

    // Apply via chrome.action.setIcon (MV3)
    chrome.action.setIcon({ path: message.paths }, () => {
      if (chrome.runtime.lastError) {
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
      } else {
        // Persist so icon survives service worker restarts
        chrome.storage.local.set({ sentinel_toolbar_icon: variantId });
        sendResponse({ success: true });
      }
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
