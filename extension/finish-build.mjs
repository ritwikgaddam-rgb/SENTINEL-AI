import { copyFileSync } from 'node:fs';

// Vite already copies public assets, including logos and model parameters.
copyFileSync(new URL('./manifest.json', import.meta.url), new URL('./dist/manifest.json', import.meta.url));
copyFileSync(new URL('./src/content/gmailOverlay.css', import.meta.url), new URL('./dist/gmailOverlay.css', import.meta.url));
