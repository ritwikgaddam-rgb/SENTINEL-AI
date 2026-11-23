/**
 * Sentinel AI — Gmail API Utility
 * All interactions with the Gmail REST API go through this module.
 * Authentication uses chrome.identity.getAuthToken (native Google OAuth).
 */

const GMAIL_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';
const PEOPLE_BASE = 'https://people.googleapis.com/v1/people/me';

// ─── Token Management ───────────────────────────────────────────────────────

export async function getToken(interactive = true) {
  return new Promise((resolve, reject) => {
    if (typeof chrome === 'undefined' || !chrome.identity) {
      reject(new Error('chrome.identity is not available outside the extension.'));
      return;
    }
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(new Error(chrome.runtime.lastError?.message || 'Failed to get auth token.'));
      } else {
        resolve(token);
      }
    });
  });
}

export async function revokeToken(token) {
  return new Promise((resolve) => {
    if (!token) { resolve(); return; }
    chrome.identity.removeCachedAuthToken({ token }, async () => {
      try {
        await fetch(`https://accounts.google.com/o/oauth2/revoke?token=${token}`);
      } catch { /* silent – best-effort */ }
      resolve();
    });
  });
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
    const res = await fetch(
      `${PEOPLE_BASE}?personFields=names,emailAddresses,photos`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (res.ok) {
      const data = await res.json();
      const name = data.names?.[0]?.displayName ?? 'Google User';
      const email = data.emailAddresses?.[0]?.value ?? '';
      const picture = data.photos?.[0]?.url ?? null;
      return { name, email, picture };
    }
  } catch { /* fall through */ }

  const res = await fetch(`${GMAIL_BASE}/profile`, {
    headers: { Authorization: `Bearer ${token}` }
  });
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

function getHeader(headers = [], name) {
  return headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
}

async function fetchMessageDetail(token, messageId) {
  const res = await fetch(`${GMAIL_BASE}/messages/${messageId}?format=full`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error(`Message fetch failed: ${res.status}`);
  return res.json();
}

export async function fetchRecentEmails(token, maxResults = 20, query = 'in:inbox') {
  const listUrl = `${GMAIL_BASE}/messages?maxResults=${maxResults}&q=${encodeURIComponent(query)}`;
  const listRes = await fetch(listUrl, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!listRes.ok) {
    if (listRes.status === 401) throw new Error('TOKEN_EXPIRED');
    throw new Error(`Gmail list failed: ${listRes.status}`);
  }
  const listData = await listRes.json();
  const messages = listData.messages ?? [];
  if (messages.length === 0) return [];

  const toFetch = messages.slice(0, Math.min(maxResults, 20));
  const details = await Promise.allSettled(
    toFetch.map(m => fetchMessageDetail(token, m.id))
  );

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
        date: getHeader(headers, 'date') || '',
        snippet: msg.snippet || '',
        body,
        labelIds: msg.labelIds ?? [],
        isUnread: (msg.labelIds ?? []).includes('UNREAD')
      };
    });
}

export async function scanEmailWithBackend(backendUrl, emailObj) {
  const res = await fetch(`${backendUrl}/api/scan-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: emailObj.body || emailObj.snippet, sender: emailObj.sender })
  });
  if (!res.ok) throw new Error('Backend scan failed');
  return res.json();
}