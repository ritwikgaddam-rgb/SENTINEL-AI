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
  // Select full logo variant based on theme and mode
  // Using exact provided SVGs with aspect ratio preserved (height only)
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
          title={backendOnline ? "Backend API & SQLite connected" : "Backend offline (Local fallback active)"}
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

        {/* Cold vs Warm Switch Pill */}
        <button
          className={`icon-btn ${theme === 'warm' ? 'active' : ''}`}
          onClick={onToggleTheme}
          title={theme === 'cold' ? 'Switch to Warm Ember Theme (#541504)' : 'Switch to Cold Sapphire Theme (#03094b)'}
        >
          <span style={{ fontSize: '12px' }}>{theme === 'cold' ? '❄️' : '🔥'}</span>
        </button>

        {/* Dark vs Light Mode Toggle */}
        <button
          className="icon-btn"
          onClick={onToggleMode}
          title={mode === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          <span style={{ fontSize: '13px' }}>{mode === 'dark' ? '☀️' : '🌙'}</span>
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
          title="Extension Settings"
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
