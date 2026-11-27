import { copyFile, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test, mock } from 'node:test';

async function moduleURL(path) {
  const source = await readFile(new URL(path, import.meta.url), 'utf8');
  return 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
}
const localURL = await moduleURL('../extension/src/popup/localApi.js');
const { localApi } = await import(localURL);
const gmailSource = (await readFile(new URL('../extension/src/popup/gmailApi.js', import.meta.url), 'utf8'))
  .replace("'./localApi'", JSON.stringify(localURL));
const gmail = await import('data:text/javascript;base64,' + Buffer.from(gmailSource).toString('base64'));

test('the standard build includes the shared public Chrome identity and read-only Gmail scope', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-gmail-build-'));
  try {
    for (const file of ['finish-build.mjs', 'manifest.json', 'src/content/gmailOverlay.css']) {
      const target = join(directory, file);
      await mkdir(dirname(target), {recursive: true});
      await copyFile(new URL('../extension/' + file, import.meta.url), target);
    }
    await mkdir(join(directory, 'dist'));
    const build = spawnSync(process.execPath, ['finish-build.mjs'], {
      cwd: directory, env: {...process.env, SENTINELAI_GOOGLE_CLIENT_ID: ''},
    });
    assert.equal(build.status, 0, build.stderr.toString());
    const source = await readFile(join(directory, 'manifest.json'), 'utf8');
    assert.equal(await readFile(join(directory, 'dist/manifest.json'), 'utf8'), source);
    const {key, oauth2, permissions, host_permissions: hosts} = JSON.parse(source);
    const publicKey = Buffer.from(key, 'base64');
    assert.equal(createPublicKey({key: publicKey, format: 'der', type: 'spki'}).type, 'public');
    const alphabet = 'abcdefghijklmnop';
    const extensionId = createHash('sha256').update(publicKey).digest('hex').slice(0, 32)
      .replace(/[0-9a-f]/g, digit => alphabet[parseInt(digit, 16)]);
    assert.equal(extensionId, 'ljhaekkkeoaajonchnhaaepfcelccbpd');
    assert.deepEqual(Object.keys(oauth2).sort(), ['client_id', 'scopes']);
    assert.match(oauth2.client_id, /^\d+-[a-z0-9]+\.apps\.googleusercontent\.com$/);
    assert.deepEqual(oauth2.scopes, ['https://www.googleapis.com/auth/gmail.readonly']);
    assert.ok(permissions.includes('identity'));
    assert.deepEqual(hosts.filter(host => host.endsWith('googleapis.com/*')).sort(), [
      'https://gmail.googleapis.com/*', 'https://oauth2.googleapis.com/*',
    ]);
  } finally {
    await rm(directory, {recursive: true, force: true});
  }
});

test('mailbox identity comes from Gmail using the read-only token', async () => {
  const fetch = mock.method(globalThis, 'fetch', async () =>
    Response.json({emailAddress: 'fixture@example.org'}));
  try {
    assert.deepEqual(await gmail.fetchUserProfile('fixture-token'), {
      name: 'fixture', email: 'fixture@example.org', picture: null,
    });
    assert.equal(fetch.mock.callCount(), 1);
    const [url, options] = fetch.mock.calls[0].arguments;
    assert.equal(url, 'https://gmail.googleapis.com/gmail/v1/users/me/profile');
    assert.equal(options.headers.Authorization, 'Bearer fixture-token');
  } finally { fetch.mock.restore(); }
});

test('private backend requests select loopback, preserve body and refuse redirects', async () => {
  const fetch = mock.method(globalThis, 'fetch', async () => new Response('{}'));
  try {
    await assert.rejects(() => localApi('https://example.org', '/api/scan-email'));
    assert.equal(fetch.mock.callCount(), 0);
    const body = JSON.stringify({text: 'Synthetic text'});
    await localApi('http://127.0.0.1:8000/', '/api/scan-email', { method: 'POST', body });
    const [url, options] = fetch.mock.calls[0].arguments;
    assert.equal(url, 'http://127.0.0.1:8000/api/scan-email');
    assert.equal(options.body, body);
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal);
  } finally { fetch.mock.restore(); }
});

test('expired Gmail details surface an expired session', async () => {
  const fetch = mock.method(globalThis, 'fetch', async url => url.includes('messages?') ?
    Response.json({ messages: [{ id: 'fixture' }] }) : new Response(null, { status: 401 }));
  try {
    await assert.rejects(() => gmail.fetchRecentEmails('fixture-token'), /TOKEN_EXPIRED/);
  } finally { fetch.mock.restore(); }
});

test('Gmail message extraction skips attachments and preserves requested headers', async () => {
  const fetch = mock.method(globalThis, 'fetch', async url => url.includes('messages?') ?
    Response.json({ messages: [{ id: 'fixture' }] }) : Response.json({
      id: 'fixture', payload: {
        headers: [{name: 'Subject', value: 'School meeting'}, {name: 'Reply-To', value: 'school@example.org'}],
        parts: [
          {mimeType: 'text/plain', filename: 'attachment.txt', body: {data: btoa('Attachment fixture')}},
          {mimeType: 'text/plain', body: {data: btoa('Meet in the library.')}}
        ]
      }
    }));
  try {
    const [email] = await gmail.fetchRecentEmails('fixture-token');
    assert.deepEqual([email.subject, email.replyTo, email.body],
      ['School meeting', 'school@example.org', 'Meet in the library.']);
  } finally { fetch.mock.restore(); }
});

test('Google revocation carries the token in a POST body', async () => {
  const fetch = mock.method(globalThis, 'fetch', async () => new Response(null));
  try {
    await gmail.revokeToken('fixture-token');
    const [url, options] = fetch.mock.calls[0].arguments;
    assert.equal(url, 'https://oauth2.googleapis.com/revoke');
    assert.equal(options.method, 'POST');
    assert.equal(options.body.get('token'), 'fixture-token');
    assert.equal(options.redirect, 'error');
  } finally { fetch.mock.restore(); }
});

test('Google sign-in runs only when the extension was configured for OAuth', async () => {
  const previousChrome = globalThis.chrome;
  const getAuthToken = mock.fn((_options, callback) => callback('fixture-token'));
  try {
    globalThis.chrome = {identity: {getAuthToken}, runtime: {getManifest: () => ({})}};
    await assert.rejects(() => gmail.getToken(), /unavailable/);
    assert.equal(getAuthToken.mock.callCount(), 0);
    chrome.runtime.getManifest = () => ({oauth2: {client_id: 'fixture-public-id'}});
    assert.equal(await gmail.getToken(), 'fixture-token');
    assert.equal(getAuthToken.mock.callCount(), 1);
  } finally {
    if (previousChrome === undefined) delete globalThis.chrome;
    else globalThis.chrome = previousChrome;
  }
});
