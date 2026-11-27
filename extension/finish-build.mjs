import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';

const manifest = JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'));
const clientId = process.env.SENTINELAI_GOOGLE_CLIENT_ID?.trim();
if (clientId) {
  if (!/^\d+-[a-z0-9]+\.apps\.googleusercontent\.com$/.test(clientId)) {
    throw new Error('SENTINELAI_GOOGLE_CLIENT_ID must be a public Google OAuth client ID.');
  }
  manifest.oauth2 = {
    client_id: clientId,
    scopes: [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
  };
  manifest.permissions.push('identity');
  manifest.host_permissions.push(
    'https://gmail.googleapis.com/*',
    'https://people.googleapis.com/*',
    'https://oauth2.googleapis.com/*',
  );
}

// Vite already copies public assets, including logos and model parameters.
writeFileSync(new URL('./dist/manifest.json', import.meta.url), JSON.stringify(manifest, null, 2) + '\n');
copyFileSync(new URL('./src/content/gmailOverlay.css', import.meta.url), new URL('./dist/gmailOverlay.css', import.meta.url));
