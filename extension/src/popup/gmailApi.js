/**
 * Sentinel AI — Gmail API Utility
 * All interactions with the Gmail REST API go through this module.
 * Authentication uses chrome.identity.getAuthToken (native Google OAuth).
 */

const GMAIL_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';
const PEOPLE_BASE = 'https://people.googleapis.com/v1/people/me';

// ─── Token Management ───────────────────────────────────────────────────────

/**
 * Get a valid OAuth access token interactively.
 * Returns the token string or throws on failure.
 */
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

/**
 * Revoke and clear a cached token so the user is effectively signed out.
 */
export async function revokeToken(token) {
  return new Promise((resolve) => {
    if (!token) { resolve(); return; }
    chrome.identity.removeCachedAuthToken({ token }, async () => {
      // Also hit the Google revoke endpoint so the grant is fully removed
      try {
        await fetch(`https://accounts.google.com/o/oauth2/revoke?token=${token}`);
      } catch { /* silent – best-effort */ }
      resolve();
    });
  });
}

/**
 * Fetch a fresh non-interactive token to check if the user is still signed in.
 * Returns null instead of throwing.
 */
export async function getTokenSilent() {
  try {
    return await getToken(false);
  } catch {
    return null;
  }
}

// ─── User Profile ────────────────────────────────────────────────────────────

/**
 * Fetch the signed-in user's Google profile (name, email, photo).
 */
export async function fetchUserProfile(token) {
  // Try People API first for richer data
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

  // Fallback: Gmail profile endpoint (always available with gmail.readonly)
  const res = await fetch(`${GMAIL_BASE}/profile`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error(`Profile fetch failed: ${res.status}`);
  const data = await res.json();
  return { name: data.emailAddress?.split('@')[0] ?? 'Google User', email: data.emailAddress ?? '', picture: null };
}

// ─── Gmail Message Fetching ──────────────────────────────────────────────────

/**
 * Decode a base64url-encoded Gmail message part body.
 */
function decodeBody(encoded) {
  if (!encoded) return '';
  try {
    // base64url → base64
    const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    return decodeURIComponent(
      atob(b64)
        .split('')
        .map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('')
    );
  } catch {
    return '';
  }
}

/**
 * Recursively extract the plain-text body from a MIME part tree.
 */
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

/**
 * Extract a named header value from a message payload.
 */
function getHeader(headers = [], name) {
  return headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
}

/**
 * Fetch a single message's full details.
 */
async function fetchMessageDetail(token, messageId) {
  const res = await fetch(`${GMAIL_BASE}/messages/${messageId}?format=full`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error(`Message fetch failed: ${res.status}`);
  return res.json();
}

/**
 * Fetch the N most recent inbox messages and return structured objects.
 *
 * @param {string} token  - OAuth access token
 * @param {number} maxResults - how many messages to fetch (default 20)
 * @param {string} query  - Gmail search query (default: unread inbox)
 * @returns {Promise<Array>} - array of { id, threadId, subject, sender, snippet, body, date, labelIds }
 */
export async function fetchRecentEmails(token, maxResults = 20, query = 'in:inbox') {
  // 1. Get message list
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

  // 2. Fetch each message in parallel (cap at 10 to avoid rate limits)
  const toFetch = messages.slice(0, Math.min(maxResults, 20));
  const details = await Promise.allSettled(
    toFetch.map(m => fetchMessageDetail(token, m.id))
  );

  return details
    .filter(r => r.status === 'fulfilled')
    .map(r => {
      const msg = r.value;
      const headers = msg.payload?.headers ?? [];
      const body = extractPlainText(msg.payload) || msg.snippet || '';
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

/**
 * Convenience: scan a fetched email object against the backend.
 */
export async function scanEmailWithBackend(backendUrl, emailObj) {
  const res = await fetch(`${backendUrl}/api/scan-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: emailObj.body || emailObj.snippet, sender: emailObj.sender })
  });
  if (!res.ok) throw new Error('Backend scan failed');
  return res.json();
}
