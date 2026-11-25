import { localApi } from '../localApi';
import React, { useState, useEffect } from 'react';

// Icon variants for toolbar icon picker
const ICON_VARIANTS = [
  { id: 'purple_minimal', label: 'Cold', desc: 'Sentinel', preview: 'logos/purple_minimal_48.png' },
  { id: 'orange_minimal', label: 'Warm', desc: 'Sentinel', preview: 'logos/orange_minimal_48.png' },
  { id: 'purple_emblem', label: 'Cold Emblem', desc: 'Shield', preview: 'logos/purple_emblem_48.png', transparent: true },
  { id: 'orange_emblem', label: 'Warm Emblem', desc: 'Shield', preview: 'logos/orange_emblem_48.png', transparent: true },
];

export default function SettingsModal({
  isOpen,
  onClose,
  theme, setTheme,
  mode,  setMode,
  settings, updateSettings,
  backendUrl, setBackendUrl,
  backendOnline, checkBackendHealth,
  // Google OAuth props (Auth0 completely removed)
  googleUser,
  authLoading,
  onSignIn,
  onSignOut,
}) {
  const [testingPing, setTestingPing]   = useState(false);
  const [pingResult, setPingResult]     = useState(null);
  const [selectedIcon, setSelectedIcon] = useState(
    () => localStorage.getItem('sentinel_toolbar_icon') || 'purple_minimal'
  );
  const [iconApplied, setIconApplied]   = useState(false);
  const [iconError, setIconError]       = useState(null);

  if (!isOpen) return null;

  // ── Backend ping ────────────────────────────────────────────────────────
  const handleTestConnection = async () => {
    setTestingPing(true);
    setPingResult(null);
    const start = performance.now();
    try {
      const res = await localApi(backendUrl, '/api/health');
      const latency = Math.round(performance.now() - start);
      if (res.ok) {
        setPingResult({ success: true, latency });
        checkBackendHealth();
      } else {
        setPingResult({ success: false, error: `HTTP ${res.status}` });
      }
    } catch {
      setPingResult({ success: false, error: 'Connection refused — is backend/server.py running?' });
    } finally {
      setTestingPing(false);
    }
  };

  // ── Toolbar icon picker ─────────────────────────────────────────────────
  const applyToolbarIcon = (variantId) => {
    const variant = ICON_VARIANTS.find(v => v.id === variantId);
    if (!variant) return;
    setIconError(null);
    setIconApplied(false);
    if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) {
      setIconError('Chrome extension API is unavailable.');
      return;
    }

    chrome.runtime.sendMessage({ type: 'SET_TOOLBAR_ICON', variantId }, (response) => {
      const error = chrome.runtime.lastError?.message || response?.error;
      if (error || !response?.success) {
        setIconError(error || 'Could not save the toolbar icon.');
        return;
      }

      setSelectedIcon(variantId);
      localStorage.setItem('sentinel_toolbar_icon', variantId);
      setIconApplied(true);
      setTimeout(() => setIconApplied(false), 2000);
    });
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content animate-slide-up">

        {/* ── Header ── */}
        <div className="modal-header">
          <h3 className="modal-title">Sentinel AI Settings</h3>
          <button className="icon-btn" onClick={onClose} title="Close">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="14" height="14">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="settings-list">

          {/* ── Google Account ─────────────────────────────────────────── */}
          <div className="card-section" style={{ border: '1px solid var(--border-highlight)' }}>
            <div className="card-title">
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                {/* Google "G" mark SVG */}
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                Google Account
              </span>
              <span className={`status-badge ${googleUser ? 'safe' : 'suspicious'}`}>
                {googleUser ? 'Connected' : 'Not Connected'}
              </span>
            </div>

            {googleUser ? (
              /* Signed-in state */
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {googleUser.picture ? (
                    <img src={googleUser.picture} alt="Profile" style={{ width: '32px', height: '32px', borderRadius: '50%' }} />
                  ) : (
                    <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--accent-color)', color: 'var(--text-inverted)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '12px' }}>
                      {googleUser.name?.charAt(0).toUpperCase() || 'G'}
                    </div>
                  )}
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)' }}>{googleUser.name}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{googleUser.email}</div>
                  </div>
                </div>
                <button className="btn-secondary" style={{ height: '28px', fontSize: '11px', paddingLeft: '11px', paddingRight: '11px' }} onClick={onSignOut}>
                  Disconnect
                </button>
              </div>
            ) : (
              /* Signed-out state */
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  Connect your Google account to scan your Gmail inbox for phishing threats automatically.
                </p>
                <button
                  className="btn-primary"
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
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
                      {/* Google G mark */}
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
            )}
          </div>

          {/* ── Color Theme ──────────────────────────────────────────────── */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Color Theme</span>
              <span className="setting-desc">Primary hue scheme</span>
            </div>
            <div className="theme-selector-chips">
              <button className={`theme-chip ${theme === 'cold' ? 'active' : ''}`} onClick={() => setTheme('cold')} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07L19.07 4.93"></path>
                </svg>
                Cold
              </button>
              <button className={`theme-chip ${theme === 'warm' ? 'active' : ''}`} onClick={() => setTheme('warm')} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path>
                </svg>
                Warm
              </button>
            </div>
          </div>

          {/* ── Appearance ───────────────────────────────────────────────── */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Appearance</span>
              <span className="setting-desc">Interface light or dark</span>
            </div>
            <div className="theme-selector-chips">
              <button className={`theme-chip ${mode === 'dark' ? 'active' : ''}`} onClick={() => setMode('dark')} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>
                Dark
              </button>
              <button className={`theme-chip ${mode === 'light' ? 'active' : ''}`} onClick={() => setMode('light')} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="4"></circle>
                  <line x1="12" y1="2" x2="12" y2="4"></line><line x1="12" y1="20" x2="12" y2="22"></line>
                  <line x1="2" y1="12" x2="4" y2="12"></line><line x1="20" y1="12" x2="22" y2="12"></line>
                </svg>
                Light
              </button>
            </div>
          </div>

          {/* ── Toolbar Icon Picker ───────────────────────────────────────── */}
          <div className="card-section" style={{ padding: '12px 14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div>
                <span className="setting-label">Toolbar Icon</span>
                <span className="setting-desc" style={{ display: 'block' }}>Icon shown in the Chrome bar</span>
              </div>
              {iconApplied && (
                <span style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--color-safe)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" width="11" height="11">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Applied
                </span>
              )}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '7px' }}>
              {ICON_VARIANTS.map(variant => {
                const isActive = selectedIcon === variant.id;
                return (
                  <button key={variant.id} onClick={() => applyToolbarIcon(variant.id)} style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '7px',
                    padding: '10px 8px', borderRadius: '10px',
                    border: isActive ? '2px solid var(--accent-primary)' : '1.5px solid var(--border-subtle)',
                    background: isActive ? 'var(--surface-highlight)' : 'var(--surface-card)',
                    cursor: 'pointer', transition: 'all 0.18s cubic-bezier(0.16,1,0.3,1)', position: 'relative', outline: 'none'
                  }}>
                    <div style={{ width: '36px', height: '36px', borderRadius: '8px', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center', background: variant.transparent ? 'transparent' : variant.id.startsWith('orange') ? '#541504' : '#03094b', border: `1px solid ${variant.id.startsWith('orange') ? 'rgba(255,120,88,0.3)' : 'rgba(88,120,255,0.3)'}` }}>
                      <img src={variant.preview} alt={variant.label} style={{ height: '24px', width: 'auto', objectFit: 'contain', display: 'block' }} onError={e => { e.target.style.display = 'none'; }} />
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-main)', lineHeight: 1.2 }}>{variant.label}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '2px' }}>{variant.desc}</div>
                    </div>
                    {isActive && (
                      <div style={{ position: 'absolute', top: '5px', right: '5px', width: '14px', height: '14px', borderRadius: '50%', background: 'var(--accent-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" width="8" height="8"><polyline points="20 6 9 17 4 12" /></svg>
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
            {iconError && (
              <div role="alert" style={{ color: 'var(--color-danger)', fontSize: '10.5px', marginTop: '8px' }}>
                {iconError}
              </div>
            )}
          </div>

          {/* ── Feature Toggles ───────────────────────────────────────────── */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Real-Time URL Shield</span>
              <span className="setting-desc">Scan visited sites for phishing</span>
            </div>
            <label className="switch">
              <input type="checkbox" checked={settings.urlShield} onChange={e => updateSettings('urlShield', e.target.checked)} />
              <span className="slider"></span>
            </label>
          </div>

          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Gmail In-Page Guardian</span>
              <span className="setting-desc">Grammarly-style overlay in Gmail</span>
            </div>
            <label className="switch">
              <input type="checkbox" checked={settings.gmailOverlay} onChange={e => updateSettings('gmailOverlay', e.target.checked)} />
              <span className="slider"></span>
            </label>
          </div>

          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Auto-Detect Aadhaar IDs</span>
              <span className="setting-desc">Flag 12-digit Indian national IDs</span>
            </div>
            <label className="switch">
              <input type="checkbox" checked={settings.autoAadhaar} onChange={e => updateSettings('autoAadhaar', e.target.checked)} />
              <span className="slider"></span>
            </label>
          </div>

          {/* ── Backend Connection ────────────────────────────────────────── */}
          <div className="card-section" style={{ marginTop: '4px' }}>
            <span className="setting-label" style={{ display: 'block', marginBottom: '6px' }}>Backend API & SQLite Server</span>
            <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
              <input type="text" className="input-clean" value={backendUrl} onChange={e => setBackendUrl(e.target.value)} placeholder="http://127.0.0.1:8000" />
              <button className="btn-secondary" style={{ padding: '0 10px', fontSize: '11px', whiteSpace: 'nowrap' }} onClick={handleTestConnection} disabled={testingPing}>
                {testingPing ? 'Pinging...' : 'Test Ping'}
              </button>
            </div>
            {pingResult && (
              <div style={{ fontSize: '11px', padding: '6px 8px', borderRadius: '4px', background: pingResult.success ? 'var(--color-safe-bg)' : 'var(--color-danger-bg)', color: pingResult.success ? 'var(--color-safe)' : 'var(--color-danger)', border: `1px solid ${pingResult.success ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}` }}>
                {pingResult.success
                  ? `Connected (${pingResult.latency}ms) - SQLite & heuristic models active`
                  : `Offline - ${pingResult.error}`}
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
