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

## Run the web preview or Chrome extension

Follow the [repository setup instructions](../README.md). Build into `extension/build-v2` to preserve the historical tracked `dist` directory, then select that new directory in Chrome's **Load unpacked** dialog.

The extension keeps the existing themes and Gmail sign-in. It adds individual email link evidence, local contextual redaction and review, active-page scanning, and opt-in numeric feature collection. The watch toggle runs for the current document only. See the [V2 audit and evaluation](../V2_REPORT.md) for limitations and the Gmail and Chrome manual test checklist.
