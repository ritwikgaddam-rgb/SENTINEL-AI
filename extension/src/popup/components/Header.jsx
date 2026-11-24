import React from 'react';

export default function Header({
  theme,
  mode,
  onToggleTheme,
  onToggleMode,
  onOpenSettings,
  onOpenHistory,
  backendOnline
}) {
  let logoSrc = "logos/SentinelAILogoFull.svg";
  if (theme === "warm") {
    logoSrc = "logos/SentinelAILogoTotal-NoBG(Orange).svg";
  }

  return (
    <header className="app-header">
      <div className="brand-wrapper" title="Sentinel AI Security & Privacy Guard">
        <img
          src={logoSrc}
          alt="Sentinel AI"
          className="brand-logo-img"
        />
      </div>

      <div className="header-actions">
        {/* Backend Online status dot */}
        <span
          title={backendOnline ? "Backend API & SQLite connected" : "Backend offline (Run ./start_backend.sh)"}
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: backendOnline ? '#10b981' : '#f59e0b',
            boxShadow: backendOnline ? '0 0 6px rgba(16, 185, 129, 0.6)' : 'none',
            display: 'inline-block',
            marginRight: '4px'
          }}
        />

        {/* Cold vs Warm Switch Pill with Minimalist SVG */}
        <button
          className={`icon-btn ${theme === 'warm' ? 'active' : ''}`}
          onClick={onToggleTheme}
          title={theme === 'cold' ? 'Switch to Warm Theme (#541504)' : 'Switch to Cold Theme (#03094b)'}
        >
          {theme === 'cold' ? (
            /* Sleek Ice Crystal / Diamond Vector */
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07L19.07 4.93"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          ) : (
            /* Sleek Ember Flame Vector */
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path>
            </svg>
          )}
        </button>

        {/* Dark vs Light Mode Toggle with Clean Geometric Sun/Moon SVGs */}
        <button
          className="icon-btn"
          onClick={onToggleMode}
          title={mode === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {mode === 'dark' ? (
            /* Minimalist Sun */
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="4"></circle>
              <line x1="12" y1="2" x2="12" y2="5"></line>
              <line x1="12" y1="19" x2="12" y2="22"></line>
              <line x1="2" y1="12" x2="5" y2="12"></line>
              <line x1="19" y1="12" x2="22" y2="12"></line>
              <line x1="4.93" y1="4.93" x2="7.05" y2="7.05"></line>
              <line x1="16.95" y1="16.95" x2="19.07" y2="19.07"></line>
              <line x1="4.93" y1="19.07" x2="7.05" y2="16.95"></line>
              <line x1="16.95" y1="7.05" x2="19.07" y2="4.93"></line>
            </svg>
          ) : (
            /* Minimalist Crescent Moon */
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
            </svg>
          )}
        </button>

        {/* History Modal Trigger */}
        <button
          className="icon-btn"
          onClick={onOpenHistory}
          title="Scan & Audit History"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
        </button>

        {/* Settings Modal Trigger */}
        <button
          className="icon-btn"
          onClick={onOpenSettings}
          title="Extension Settings & Auth0"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </button>
      </div>
    </header>
  );
}
