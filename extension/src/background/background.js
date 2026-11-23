/**
 * Sentinel AI - Background Service Worker (Manifest V3)
 * Handles lifecycle, tab monitoring, and context menu actions.
 */

const BACKEND_URL = "http://127.0.0.1:8000";

// Initialize default settings on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(
    ["sentinel_theme", "sentinel_mode", "sentinel_urlShield", "sentinel_gmailOverlay"],
    (result) => {
      const defaults = {};
      if (!result.sentinel_theme) defaults.sentinel_theme = "cold";
      if (!result.sentinel_mode) defaults.sentinel_mode = "dark";
      if (typeof result.sentinel_urlShield === "undefined") defaults.sentinel_urlShield = true;
      if (typeof result.sentinel_gmailOverlay === "undefined") defaults.sentinel_gmailOverlay = true;

      chrome.storage.local.set(defaults);
    }
  );

  // Create context menu for quick scanning
  chrome.contextMenus.create({
    id: "sentinel_scan_selection",
    title: "Inspect Selected Text with Sentinel AI",
    contexts: ["selection"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "sentinel_scan_selection" && info.selectionText) {
    // Open popup or send message
    console.log("[Sentinel AI] Selected text for audit:", info.selectionText.substring(0, 50));
  }
});

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_URL") {
    fetch(`${BACKEND_URL}/api/scan-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: message.url })
    })
      .then((res) => res.json())
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep sendResponse open for async
  }
});
