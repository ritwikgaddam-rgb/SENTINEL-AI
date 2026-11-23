# Sentinel AI - Browser Extension & Backend

Next-generation browser security and identity privacy guard against phishing campaigns, social engineering, and sensitive data exposure (Aadhaar IDs, phone numbers, emails).

---

## 🎨 Theme & Design System

The extension comes with two carefully crafted color palettes inspired by macOS native applications:
- **Cold Sapphire (Default):** `#03094b` with midnight gradients, glassmorphism, and indigo accents.
- **Warm Ember (Switchable):** `#541504` with deep terracotta ember tones and warm accents.
- **Modes:** Both themes support **Dark Mode** and **Light Mode**.
- **Logos:** Strictly utilizes the provided SVGs with preserved aspect ratios. The loading state features a Discord-style rotating Sentinel AI emblem.
- **Typography:** Inter with tight letter-spacing (`-0.022em`) for a crisp, native feel.
- **Easy CSS Customization:** All colors, radii, shadows, and transitions are organized in `extension/src/theme.css`.

---

## 🚀 How to Run the App

### 1. Start the Python & SQLite Backend Server
From the workspace root, run:
```bash
python3 backend/server.py 8000
```
This automatically initializes the SQLite database at `backend/sentinel_ai.db` and starts the REST API on `http://127.0.0.1:8000`.

### 2. Build the Extension
```bash
cd extension
npm run build
```
This outputs the production-ready extension into `extension/dist/`.

### 3. Load into Google Chrome (or any Chromium browser)
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle switch in the top right).
3. Click **Load unpacked**.
4. Select the `extension/dist` folder.
5. The Sentinel AI icon will appear in your browser toolbar!

---

## 🛡️ Key Features

1. **Active URL Shield:**
   - Real-time phishing heuristic & ML feature analysis.
   - Detection of raw IP domains, abnormal URL length, brand impersonation, and non-HTTPS traffic.
   - Explanatory markers showing why a site is flagged.

2. **Email Phishing Scanner:**
   - Analyzes email subjects and bodies for urgent psychological triggers, credential harvesting requests, and rogue embedded links.
   - Displays risk score and categorized threat markers.

3. **In-Page Gmail Guardian (Grammarly-Style):**
   - **Reading View:** Injects an elegant floating Sentinel badge into email headers on `mail.google.com`. Clicking the badge opens a native popover audit card.
   - **Compose View:** Adds a circular Sentinel emblem at the bottom-right of the compose window. It continuously monitors typed drafts for Indian Aadhaar IDs and phone numbers, allowing **1-click automatic redaction** before sending.

4. **Privacy Guard:**
   - Detects 12-digit Indian Aadhaar numbers, phone numbers (`+91`), and emails.
   - Live real-time redactor with 1-click clipboard copy.

5. **SQLite Database & History:**
   - Logs all scan events and privacy audits into `backend/sentinel_ai.db`.
   - Access history directly from the extension's history modal.
