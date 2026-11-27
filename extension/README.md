# SentinelAI Chrome extension

From the repository root, run `npm --prefix extension ci` and `npm --prefix extension run build`. Load `extension/dist` unpacked in Chrome. See the [installation guide](../INSTALL.md) for the backend, Gmail consent and regression checks.

Vite builds the React popup and scripts from `src/`. The manifest, offline model parameters and official brand assets are included in the build. Theme variables live in `src/theme.css`.
