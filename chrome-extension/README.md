# SentinelAI Chrome extension

This Manifest V3 package provides the official SentinelAI toolbar mark and a small theme preview. It has no browsing permissions.

Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select this directory. The popup lets you switch the toolbar mark and wordmark between navy and orange. Chrome starts with the navy toolbar icon and restores the selected appearance when the popup opens.

The PNGs are shipped with the manifest for unpacked or packaged use. To regenerate them after changing the official artwork, install the dependencies in `mac-app/`, then run `node assets/logos/build-icons.mjs` from the repository root. [Chrome extension icon reference](https://developer.chrome.com/docs/extensions/reference/manifest/icons)
