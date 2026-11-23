import React, { useState } from 'react';

export default function SettingsModal({
  isOpen,
  onClose,
  theme,
  setTheme,
  mode,
  setMode,
  settings,
  updateSettings,
  backendUrl,
  setBackendUrl,
  backendOnline,
  checkBackendHealth,
  auth0User,
  onAuth0Login,
  onAuth0Logout
}) {
  const [testingPing, setTestingPing] = useState(false);
  const [pingResult, setPingResult] = useState(null);
  const [auth0Domain, setAuth0Domain] = useState(() => localStorage.getItem('sentinel_auth0_domain') || 'sentinel-ai.us.auth0.com');
  const [auth0ClientId, setAuth0ClientId] = useState(() => localStorage.getItem('sentinel_auth0_client_id') || 'aBc123SentinelClientId');

  if (!isOpen) return null;

  const handleTestConnection = async () => {
    setTestingPing(true);
    setPingResult(null);
    const start = performance.now();
    try {
      const res = await fetch(`${backendUrl}/api/health`);
      const latency = Math.round(performance.now() - start);
      if (res.ok) {
        const data = await res.json();
        setPingResult({ success: true, latency, data });
        checkBackendHealth();
      } else {
        setPingResult({ success: false, error: `HTTP ${res.status}` });
      }
    } catch {
      setPingResult({ success: false, error: "Connection Refused (Check if backend/server.py is running)" });
    } finally {
      setTestingPing(false);
    }
  };

  const handleSaveAuth0Config = () => {
    localStorage.setItem('sentinel_auth0_domain', auth0Domain);
    localStorage.setItem('sentinel_auth0_client_id', auth0ClientId);
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content animate-slide-up">
        <div className="modal-header">
          <h3 className="modal-title">Sentinel AI Settings</h3>
          <button className="icon-btn" onClick={onClose} title="Close Settings">
            ✕
          </button>
        </div>

        <div className="settings-list">
          {/* Auth0 Identity & Gmail Scanning Section */}
          <div className="card-section" style={{ border: '1px solid var(--border-highlight)' }}>
            <div className="card-title">
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '15px' }}>🔐</span> Auth0 & Gmail Sync
              </span>
              <span className={`status-badge ${auth0User ? 'safe' : 'suspicious'}`}>
                {auth0User ? 'Authenticated' : 'Not Connected'}
              </span>
            </div>

            {auth0User ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '50%',
                    background: 'var(--accent-color)',
                    color: 'var(--text-inverted)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '12px'
                  }}>
                    {auth0User.name ? auth0User.name.charAt(0).toUpperCase() : 'U'}
                  </div>
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)' }}>
                      {auth0User.name || 'Sentinel User'}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {auth0User.email}
                    </div>
                  </div>
                </div>
                <button
                  className="btn-secondary"
                  style={{ height: '28px', fontSize: '11px' }}
                  onClick={onAuth0Logout}
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  Sign in through Auth0 to grant Gmail scan permissions and enable automated inbox phishing detection.
                </p>
                <button
                  className="btn-primary"
                  style={{ width: '100%' }}
                  onClick={onAuth0Login}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path>
                    <polyline points="10 17 15 12 10 7"></polyline>
                    <line x1="15" y1="12" x2="3" y2="12"></line>
                  </svg>
                  Connect with Auth0 (Google)
                </button>
              </div>
            )}
          </div>

          {/* Color Palette Switcher */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Color Theme</span>
              <span className="setting-desc">Primary hue styling</span>
            </div>
            <div className="theme-selector-chips">
              <button
                className={`theme-chip ${theme === 'cold' ? 'active' : ''}`}
                onClick={() => setTheme('cold')}
              >
                ❄️ Cold (#03094b)
              </button>
              <button
                className={`theme-chip ${theme === 'warm' ? 'active' : ''}`}
                onClick={() => setTheme('warm')}
              >
                🔥 Warm (#541504)
              </button>
            </div>
          </div>

          {/* Mode Switcher */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Appearance</span>
              <span className="setting-desc">Light or dark interface</span>
            </div>
            <div className="theme-selector-chips">
              <button
                className={`theme-chip ${mode === 'dark' ? 'active' : ''}`}
                onClick={() => setMode('dark')}
              >
                🌙 Dark
              </button>
              <button
                className={`theme-chip ${mode === 'light' ? 'active' : ''}`}
                onClick={() => setMode('light')}
              >
                ☀️ Light
              </button>
            </div>
          </div>

          {/* URL Shield Toggle */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Real-Time URL Shield</span>
              <span className="setting-desc">Scan visited sites for phishing</span>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={settings.urlShield}
                onChange={(e) => updateSettings('urlShield', e.target.checked)}
              />
              <span className="slider"></span>
            </label>
          </div>

          {/* Gmail In-Page Badge Toggle */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Gmail In-Page Guardian</span>
              <span className="setting-desc">Grammarly-style overlay in Gmail</span>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={settings.gmailOverlay}
                onChange={(e) => updateSettings('gmailOverlay', e.target.checked)}
              />
              <span className="slider"></span>
            </label>
          </div>

          {/* Aadhaar Auto-Protection Toggle */}
          <div className="setting-row">
            <div className="setting-info">
              <span className="setting-label">Auto-Detect Aadhaar IDs</span>
              <span className="setting-desc">Flag 12-digit Indian national IDs</span>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={settings.autoAadhaar}
                onChange={(e) => updateSettings('autoAadhaar', e.target.checked)}
              />
              <span className="slider"></span>
            </label>
          </div>

          {/* Backend Connection */}
          <div className="card-section" style={{ marginTop: '4px' }}>
            <span className="setting-label" style={{ display: 'block', marginBottom: '6px' }}>
              Backend API & SQLite Server
            </span>
            <div style={{ display: 'flex', gap: '6px', marginBottom: '8px' }}>
              <input
                type="text"
                className="input-clean"
                value={backendUrl}
                onChange={(e) => setBackendUrl(e.target.value)}
                placeholder="http://127.0.0.1:8000"
              />
              <button
                className="btn-secondary"
                style={{ padding: '0 10px', fontSize: '11px', whiteSpace: 'nowrap' }}
                onClick={handleTestConnection}
                disabled={testingPing}
              >
                {testingPing ? "Pinging..." : "Test Ping"}
              </button>
            </div>

            {pingResult && (
              <div style={{
                fontSize: '11px',
                padding: '6px 8px',
                borderRadius: '4px',
                background: pingResult.success ? 'var(--color-safe-bg)' : 'var(--color-danger-bg)',
                color: pingResult.success ? 'var(--color-safe)' : 'var(--color-danger)',
                border: `1px solid ${pingResult.success ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`
              }}>
                {pingResult.success
                  ? `✓ Connected (${pingResult.latency}ms) — SQLite & Heuristic models active`
                  : `✗ ${pingResult.error}`}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
