import { localApi } from './localApi';
/**
 * Sentinel AI — Gmail API Utility
 * All interactions with the Gmail REST API go through this module.
 * Authentication uses chrome.identity.getAuthToken (native Google OAuth).
 */

const GMAIL_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';
const PEOPLE_BASE = 'https://people.googleapis.com/v1/people/me';

function googleFetch(url, token) {
  return fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10000),
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
}

// ─── Token Management ───────────────────────────────────────────────────────

export function gmailSignInConfigured() {
  return Boolean(globalThis.chrome?.identity?.getAuthToken &&
    globalThis.chrome.runtime?.getManifest?.()?.oauth2?.client_id);
}

export async function getToken(interactive = true) {
  if (!gmailSignInConfigured()) throw new Error('Gmail sign-in is unavailable in this build.');
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(new Error(chrome.runtime.lastError?.message || 'Failed to get auth token.'));
      } else {
        resolve(token);
      }
    });
  });
}

function forgetCachedToken(token) {
  if (!globalThis.chrome?.identity || !token) return Promise.resolve();
  return new Promise(resolve => chrome.identity.removeCachedAuthToken({ token }, resolve));
}

export async function revokeToken(token) {
  if (!token) return;
  await forgetCachedToken(token);
  try {
    await fetch('https://oauth2.googleapis.com/revoke', {
      method: 'POST',
      body: new URLSearchParams({ token }),
      signal: AbortSignal.timeout(5000),
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  } catch { /* Local sign-out is complete even when Google is unreachable. */ }
}

export async function getTokenSilent() {
  try {
    return await getToken(false);
  } catch {
    return null;
  }
}

// ─── User Profile ────────────────────────────────────────────────────────────

export async function fetchUserProfile(token) {
  try {
    const res = await googleFetch(`${PEOPLE_BASE}?personFields=names,emailAddresses,photos`, token);
    if (res.ok) {
      const data = await res.json();
      const name = data.names?.[0]?.displayName ?? 'Google User';
      const email = data.emailAddresses?.[0]?.value ?? '';
      const picture = data.photos?.[0]?.url ?? null;
      return { name, email, picture };
    }
  } catch { /* fall through */ }

  const res = await googleFetch(`${GMAIL_BASE}/profile`, token);
  if (!res.ok) throw new Error(`Profile fetch failed: ${res.status}`);
  const data = await res.json();
  return { name: data.emailAddress?.split('@')[0] ?? 'Google User', email: data.emailAddress ?? '', picture: null };
}

// ─── Gmail Message Fetching ──────────────────────────────────────────────────

function decodeBody(encoded) {
  if (!encoded) return '';
  try {
    const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
  } catch {
    return '';
  }
}

function extractPlainText(part) {
  if (!part) return '';
  if (part.filename || part.body?.attachmentId) return '';
  if (part.mimeType === 'text/plain' && part.body?.data) {
    return decodeBody(part.body.data);
  }
  if (part.parts) {
    for (const child of part.parts) {
      const text = extractPlainText(child);
      if (text) return text;
    }
  }
  return '';
}

function extractHtmlText(part) {
  if (!part) return '';
  if (part.filename || part.body?.attachmentId) return '';
  if (part.mimeType === 'text/html' && part.body?.data) {
    const html = decodeBody(part.body.data);
    return html
      .replace(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi, '$2 ($1)')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }
  if (part.parts) {
    for (const child of part.parts) {
      const text = extractHtmlText(child);
      if (text) return text;
    }
  }
  return '';
}

function messageLinks(part) {
  if (!part || part.filename || part.body?.attachmentId) return [];
  if (part.mimeType === 'text/html' && part.body?.data && typeof document !== 'undefined') {
    // Template content stays inert, including remote images in an email.
    const template = document.createElement('template');
    template.innerHTML = decodeBody(part.body.data).slice(0, 100000);
    return [...template.content.querySelectorAll('a[href]')].slice(0, 40).map(a =>
      ({url: a.getAttribute('href'), label: a.textContent.slice(0, 200)}));
  }
  return (part.parts || []).flatMap(messageLinks).slice(0, 40);
}

function getHeader(headers = [], name) {
  return headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
}

async function fetchMessageDetail(token, messageId) {
  const res = await googleFetch(`${GMAIL_BASE}/messages/${encodeURIComponent(messageId)}?format=full`, token);
  if (res.status === 401) throw new Error('TOKEN_EXPIRED');
  if (!res.ok) throw new Error(`Message fetch failed: ${res.status}`);
  return res.json();
}

export async function fetchRecentEmails(token, maxResults = 20, query = 'in:inbox') {
  const listUrl = `${GMAIL_BASE}/messages?maxResults=${maxResults}&q=${encodeURIComponent(query)}`;
  const listRes = await googleFetch(listUrl, token);
  if (!listRes.ok) {
    if (listRes.status === 401) {
      await forgetCachedToken(token);
      throw new Error('TOKEN_EXPIRED');
    }
    throw new Error(`Gmail list failed: ${listRes.status}`);
  }
  const listData = await listRes.json();
  const messages = listData.messages ?? [];
  if (messages.length === 0) return [];

  const toFetch = messages.slice(0, Math.min(maxResults, 20));
  const details = await Promise.allSettled(
    toFetch.map(m => fetchMessageDetail(token, m.id))
  );
  if (details.some(row => row.status === 'rejected' && row.reason?.message === 'TOKEN_EXPIRED')) {
    await forgetCachedToken(token);
    throw new Error('TOKEN_EXPIRED');
  }
  if (details.every(row => row.status === 'rejected')) {
    throw new Error('Could not load messages. Try again.');
  }

  return details
    .filter(r => r.status === 'fulfilled')
    .map(r => {
      const msg = r.value;
      const headers = msg.payload?.headers ?? [];
      const body = extractPlainText(msg.payload) || extractHtmlText(msg.payload) || msg.snippet || '';
      return {
        id: msg.id,
        threadId: msg.threadId,
        subject: getHeader(headers, 'subject') || '(no subject)',
        sender: getHeader(headers, 'from') || 'Unknown Sender',
        replyTo: getHeader(headers, 'reply-to') || '',
        date: getHeader(headers, 'date') || '',
        snippet: msg.snippet || '',
        body, links: messageLinks(msg.payload),
        labelIds: msg.labelIds ?? [],
        isUnread: (msg.labelIds ?? []).includes('UNREAD')
      };
    });
}

export async function scanEmailWithBackend(backendUrl, emailObj) {
  const res = await localApi(backendUrl, '/api/scan-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: (emailObj.body || emailObj.snippet || '').slice(0, 20000),
      sender: emailObj.sender?.slice(0, 500), subject: emailObj.subject?.slice(0, 500),
      links: emailObj.links?.slice(0, 40), reply_to: emailObj.replyTo?.slice(0, 500), labels: emailObj.labelIds?.slice(0, 50) })
  });
  if (!res.ok) throw new Error('Backend scan failed');
  return res.json();
}
