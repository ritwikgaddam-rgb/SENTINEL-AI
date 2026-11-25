import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
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
