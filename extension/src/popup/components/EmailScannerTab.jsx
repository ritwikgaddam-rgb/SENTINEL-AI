import React, { useState } from 'react';
import MarkersCard from './MarkersCard';
import LogoLoader from './LogoLoader';
import { fetchRecentEmails, scanEmailWithBackend } from '../gmailApi';

// ─── Risk level helper ───────────────────────────────────────────────────────
// ─── Risk level helper ───────────────────────────────────────────────────────
function getRiskColor(level, theme, mode) {
  if (level === 'danger') return 'var(--color-danger)';
  if (level === 'suspicious') {
    return theme === 'cold' && mode === 'dark' ? '#ffffff' : 'var(--color-warning)';
  }
  return level === 'safe' ? 'var(--color-safe)' : 'var(--text-secondary)';
}

function unavailableScan() {
  return { risk_level: 'unknown', assessment: 'Analysis unavailable', safety_score: null, markers: [] };
}

function scoreLabel(result) {
  return Number.isFinite(result.safety_score) ? result.safety_score + '% Safe' : 'Score unavailable';
}

// ─── Single email result card ────────────────────────────────────────────────
// ─── Single email result card ────────────────────────────────────────────────
function InboxEmailRow({ email, onSelect, isSelected, theme, mode }) {
  return (
    <button
      onClick={() => onSelect(email)}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '3px',
        padding: '10px 12px',
        borderRadius: '8px',
        background: isSelected ? 'var(--surface-highlight)' : 'var(--surface-card)',
        border: isSelected ? '1.5px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
        cursor: 'pointer',
        textAlign: 'left',
        width: '100%',
        transition: 'all 0.15s ease',
        outline: 'none',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '6px' }}>
        <span style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
          {email.subject}
        </span>
        {email.isUnread && (
          <span style={{ background: 'var(--accent-primary)', borderRadius: '9999px', fontSize: '9px', fontWeight: 700, color: '#fff', padding: '1px 6px', flexShrink: 0 }}>
            NEW
          </span>
        )}
        {email.scanResult && (
          <span style={{ fontSize: '9px', fontWeight: 700, color: getRiskColor(email.scanResult.risk_level, theme, mode), flexShrink: 0 }}>
            {email.scanResult.risk_level === 'danger' ? 'THREAT' : email.scanResult.risk_level === 'suspicious' ? 'CAUTION' : email.scanResult.risk_level === 'safe' ? 'NO CLEAR FLAGS' : 'NO SCORE'}
          </span>
        )}
      </div>
      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {email.sender}
      </div>
      <div style={{ fontSize: '10.5px', color: 'var(--text-tertiary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {email.snippet}
      </div>
    </button>
  );
}

// ─── Main component ──────────────────────────────────────────────────────────
export default function EmailScannerTab({ theme, mode, backendUrl, googleUser, accessToken, onSignIn, authLoading }) {
  // Manual paste scanner state
  const [emailText, setEmailText]     = useState('');
  const [sender, setSender]           = useState('');
  const [manualLoading, setManualLoading] = useState(false);
  const [manualResult, setManualResult]   = useState(null);
  const [scannedText, setScannedText] = useState(null);
  const [copied, setCopied]           = useState(false);

  // Gmail inbox scanner state
  const [inboxEmails, setInboxEmails]       = useState([]);
  const [inboxLoading, setInboxLoading]     = useState(false);
  const [inboxError, setInboxError]         = useState(null);
  const [selectedEmail, setSelectedEmail]   = useState(null);
  const [detailLoading, setDetailLoading]   = useState(false);
  const [detailResult, setDetailResult]     = useState(null);
  const [scannedCount, setScannedCount]     = useState(0);

  // ── Manual scanner ─────────────────────────────────────────────────────
  const handleManualScan = async () => {
    if (!emailText.trim()) return;
    setManualLoading(true);
    setManualResult(null);
    try {
      const data = await scanEmailWithBackend(backendUrl, { body: emailText, sender });
      setScannedText(emailText);
      setManualResult(data);
    } catch {
      setManualResult(unavailableScan());
    } finally {
      setManualLoading(false);
    }
  };

  const handleRedactAndCopy = async () => {
    if (scannedText !== emailText || typeof manualResult?.redacted_text !== 'string') return;
    await navigator.clipboard.writeText(manualResult.redacted_text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // ── Gmail inbox fetch & scan ───────────────────────────────────────────
  const handleFetchInbox = async () => {
    if (!accessToken) return;
    setInboxLoading(true);
    setInboxError(null);
    setInboxEmails([]);
    setSelectedEmail(null);
    setDetailResult(null);
    setScannedCount(0);

    try {
      const emails = await fetchRecentEmails(accessToken, 20);
      setInboxEmails(emails);

      // Auto-scan each email and annotate with risk
      let count = 0;
      const annotated = [...emails];
      for (let i = 0; i < annotated.length; i++) {
        try {
          const scan = await scanEmailWithBackend(backendUrl, annotated[i]);
          annotated[i] = { ...annotated[i], scanResult: scan };
        } catch {
          annotated[i] = { ...annotated[i], scanResult: unavailableScan() };
        }
        count++;
        setScannedCount(count);
        setInboxEmails([...annotated]);
      }
    } catch (err) {
      if (err.message === 'TOKEN_EXPIRED') {
        setInboxError('Session expired. Please sign in again from Settings.');
      } else {
        setInboxError(err.message || 'Failed to fetch inbox.');
      }
    } finally {
      setInboxLoading(false);
    }
  };

  const handleSelectEmail = async (email) => {
    setSelectedEmail(email);
    if (email.scanResult) {
      setDetailResult(email.scanResult);
      return;
    }
    setDetailLoading(true);
    setDetailResult(null);
    try {
      const scan = await scanEmailWithBackend(backendUrl, email);
      setDetailResult(scan);
    } catch {
      setDetailResult(unavailableScan());
    } finally {
      setDetailLoading(false);
    }
  };

  const loadSamplePhish = () => {
    setSender('security-alert@paypal-auth-verify.xyz');
    setEmailText('URGENT: Your account has been suspended due to unauthorized access. Please verify your identity and confirm your Aadhaar number 4589 1234 5678 and phone +91 9876543210 immediately to restore access within 24 hours.');
  };

  const logoSrc = theme === 'warm'
    ? 'logos/SentinelAILogoIcon-SentinelOnly(Orange).svg'
    : 'logos/SentinelAILogoIconOnlySentinel(Purple).svg';

  const threats = inboxEmails.filter(e => e.scanResult?.risk_level === 'danger');
  const cautions = inboxEmails.filter(e => e.scanResult?.risk_level === 'suspicious');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

      {/* ── Gmail Inbox Scanner (requires sign-in) ── */}
      <div className="card-section">
        <div className="card-title">
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
              <polyline points="22,6 12,13 2,6" />
            </svg>
            Gmail Inbox Scanner
          </span>
          {inboxEmails.length > 0 && (
            <span style={{ fontSize: '10.5px', color: 'var(--text-secondary)' }}>
              {scannedCount}/{inboxEmails.length} scanned
              {threats.length > 0 && <span style={{ color: 'var(--color-danger)', fontWeight: 700, marginLeft: '6px' }}> {threats.length} threat{threats.length > 1 ? 's' : ''}</span>}
              {cautions.length > 0 && (
                <span
                  style={{
                    color: theme === 'cold' && mode === 'dark' ? '#ffffff' : 'var(--color-warning)',
                    fontWeight: 700,
                    marginLeft: '4px',
                  }}
                >
                  {' '}{cautions.length} caution
                </span>
              )}
            </span>
          )}
        </div>

        {!googleUser ? (
          /* Not signed in */
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', padding: '16px 0' }}>
            <div style={{ textAlign: 'center' }}>
              <img src={logoSrc} alt="Sentinel AI" style={{ height: '36px', width: 'auto', display: 'block', margin: '0 auto 8px' }} />
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.45, maxWidth: '240px' }}>
                Sign in with Google to automatically scan your Gmail inbox for phishing threats.
              </p>
            </div>
            <button
              className="btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: '8px', paddingLeft: '14px', paddingRight: '14px' }}
              onClick={onSignIn}
              disabled={authLoading}
            >
              {authLoading ? (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="13" height="13" style={{ animation: 'spin 1s linear infinite' }}>
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                  </svg>
                  Connecting...
                </>
              ) : (
                <>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                  </svg>
                  Sign in with Google
                </>
              )}
            </button>
          </div>
        ) : (
          /* Signed in */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                Scanning as <strong style={{ color: 'var(--text-main)' }}>{googleUser.email}</strong>
              </span>
              <button
                className="btn-primary"
                style={{ height: '28px', fontSize: '11px', padding: '0 12px', display: 'flex', alignItems: 'center', gap: '5px' }}
                onClick={handleFetchInbox}
                disabled={inboxLoading}
              >
                {inboxLoading ? (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="11" height="11" style={{ animation: 'spin 1s linear infinite' }}>
                      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                    </svg>
                    Scanning...
                  </>
                ) : (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="11" height="11">
                      <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                    </svg>
                    {inboxEmails.length > 0 ? 'Re-scan Inbox' : 'Scan Inbox'}
                  </>
                )}
              </button>
            </div>

            {inboxError && (
              <div style={{ fontSize: '11.5px', color: 'var(--color-danger)', background: 'var(--color-danger-bg)', borderRadius: '7px', padding: '8px 10px', border: '1px solid rgba(239,68,68,0.3)' }}>
                {inboxError}
              </div>
            )}

            {inboxLoading && inboxEmails.length === 0 && (
              <LogoLoader theme={theme} mode={mode} text="Fetching & scanning inbox..." />
            )}

            {/* Email list */}
              {inboxEmails.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', maxHeight: '220px', overflowY: 'auto' }}>
                  {inboxEmails.map(email => (
                    <InboxEmailRow
                      key={email.id}
                      email={email}
                      isSelected={selectedEmail?.id === email.id}
                      onSelect={handleSelectEmail}
                      theme={theme}
                      mode={mode}
                    />
                  ))}
                </div>
              )}

            {/* Selected email detail */}
            {selectedEmail && (
              <div style={{ marginTop: '2px' }}>
                <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-main)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="12" height="12">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  Threat Analysis
                </div>
                {detailLoading && <LogoLoader theme={theme} mode={mode} text="Analyzing..." />}
                {detailResult && !detailLoading && (
                  <>
                    <div className="status-hero-card" style={{ marginBottom: '8px' }}>
                      <div className="shield-emblem-wrap">
                        <img src={logoSrc} alt="Emblem" className="shield-emblem-img" />
                      </div>
                      <div className="status-info">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span className={`status-badge ${detailResult.risk_level}`}>
                            {detailResult.risk_level === 'danger' ? 'Phishing Threat' : detailResult.risk_level === 'suspicious' ? 'Suspicious' : detailResult.risk_level === 'safe' ? 'No clear indicators' : 'No score'}
                          </span>
                          <span className="score-pill">{scoreLabel(detailResult)}</span>
                        </div>
                        <h4 className="status-title">{selectedEmail.subject}</h4>
                        <p className="status-desc" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          From: {selectedEmail.sender}
                        </p>
                      </div>
                    </div>
                    <MarkersCard markers={detailResult.markers} title="Email Threat Markers" />
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Manual Paste Scanner ── */}
      <div className="card-section">
        <div className="card-title">
          <span>Manual Email & Text Scanner</span>
          <button onClick={loadSamplePhish} style={{ background: 'none', border: 'none', color: 'var(--accent-color)', fontSize: '11px', cursor: 'pointer', fontWeight: 600 }}>
            Load Sample Phish
          </button>
        </div>

        <div className="input-group">
          <input type="text" className="input-clean" placeholder="Sender address (optional)" value={sender} onChange={e => setSender(e.target.value)} />
          <textarea className="textarea-clean" placeholder="Paste email body, suspicious link, or draft content..." value={emailText} onChange={e => setEmailText(e.target.value)} />
          <button className="btn-primary" onClick={handleManualScan} disabled={manualLoading || !emailText.trim()}>
            {manualLoading ? 'Analyzing...' : 'Analyze for Phishing & Leaks'}
          </button>
        </div>
      </div>

      {manualLoading && <LogoLoader theme={theme} mode={mode} text="Deep Phishing Analysis..." />}

      {manualResult && !manualLoading && (
        <>
          <div className="status-hero-card">
            <div className="shield-emblem-wrap">
              <img src={logoSrc} alt="Emblem" className="shield-emblem-img" />
            </div>
            <div className="status-info">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span className={`status-badge ${manualResult.risk_level}`}>
                  {manualResult.risk_level === 'danger' ? 'Phishing Threat' : manualResult.risk_level === 'suspicious' ? 'Suspicious Content' : manualResult.risk_level === 'safe' ? 'No clear indicators' : 'No score'}
                </span>
                <span className="score-pill">{scoreLabel(manualResult)}</span>
              </div>
              <h4 className="status-title">{manualResult.assessment || 'Email assessment'}</h4>
              <p className="status-desc">
                {manualResult.private_items_count > 0
                  ? `Identified ${manualResult.private_items_count} private identity data points.`
                  : 'No credential or identity exposure found.'}
              </p>
            </div>
          </div>

          {manualResult.private_items_count > 0 && (
            <div className="card-section" style={{ background: 'var(--surface-input)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="14" height="14" style={{ color: 'var(--accent-primary)' }}>
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                  {manualResult.private_items_count} Sensitive Items Detected
                </span>
                <button className="btn-secondary" style={{ height: '28px', fontSize: '11px', padding: '0 8px', display: 'inline-flex', alignItems: 'center', gap: '4px' }} onClick={handleRedactAndCopy} disabled={scannedText !== emailText || typeof manualResult.redacted_text !== 'string'}>
                  {copied ? (
                    <>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" width="12" height="12"><polyline points="20 6 9 17 4 12" /></svg>
                      Copied
                    </>
                  ) : 'Redact & Copy'}
                </button>
              </div>
            </div>
          )}

          <MarkersCard markers={manualResult.markers} title="Suspicious Email Markers & Cues" />
        </>
      )}
    </div>
  );
}
