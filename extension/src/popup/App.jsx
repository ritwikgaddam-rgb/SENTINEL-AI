import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import ShieldStatus from './components/ShieldStatus';
import EmailScannerTab from './components/EmailScannerTab';
import PrivacyGuardTab from './components/PrivacyGuardTab';
import SettingsModal from './components/SettingsModal';
import HistoryModal from './components/HistoryModal';
import { getToken, getTokenSilent, revokeToken, fetchUserProfile } from './gmailApi';
import '../theme.css';
import './Popup.css';

const TABS = [
  { id: 'overview', label: 'Shield', icon: (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
    </svg>
  )},
  { id: 'email', label: 'Email Guard', icon: (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
      <polyline points="22,6 12,13 2,6"></polyline>
    </svg>
  )},
  { id: 'privacy', label: 'Privacy', icon: (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
    </svg>
  )}
];

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem('sentinel_theme') || 'cold');
  const [mode, setMode] = useState(() => localStorage.getItem('sentinel_mode') || 'dark');
  const [activeTab, setActiveTab] = useState('overview');
  const [currentUrl, setCurrentUrl] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [backendUrl, setBackendUrl] = useState('http://127.0.0.1:8000');
  const [backendOnline, setBackendOnline] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);

  // ── Google OAuth user (replaces Auth0) ──────────────────────────────────
  const [googleUser, setGoogleUser] = useState(() => {
    try {
      const saved = localStorage.getItem('sentinel_google_user');
      if (saved) return JSON.parse(saved);
    } catch { /* ignore */ }
    return null;
  });
  const [authLoading, setAuthLoading] = useState(false);
  // Keep the live access token in memory only (never persisted)
  const [accessToken, setAccessToken] = useState(null);

  const [settings, setSettings] = useState({ urlShield: true, gmailOverlay: true, autoAadhaar: true });

  const navRef = useRef(null);
  const [pillStyle, setPillStyle] = useState({ transform: 'translateX(0px)', width: '0px' });

  // Sliding pill indicator
  useEffect(() => {
    if (!navRef.current) return;
    const idx = TABS.findIndex(t => t.id === activeTab);
    const buttons = navRef.current.querySelectorAll('.nav-tab-btn');
    if (buttons[idx]) {
      const btn = buttons[idx];
      setPillStyle({ transform: `translateX(${btn.offsetLeft}px)`, width: `${btn.offsetWidth}px` });
    }
  }, [activeTab]);

  // Sync theme/mode to DOM + storage
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.setAttribute('data-mode', mode);
    localStorage.setItem('sentinel_theme', theme);
    localStorage.setItem('sentinel_mode', mode);
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      chrome.storage.local.set({ sentinel_theme: theme, sentinel_mode: mode });
    }
  }, [theme, mode]);

  // On mount: check backend + get active tab + silently restore token
  useEffect(() => {
    checkBackendHealth();
    fetchActiveTabUrl();
    tryRestoreSession();
  }, [backendUrl]);

  // ── Backend ───────────────────────────────────────────────────────────────

  const checkBackendHealth = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/health`);
      setBackendOnline(res.ok);
    } catch {
      setBackendOnline(false);
    }
  };

  const fetchActiveTabUrl = () => {
    if (typeof chrome !== 'undefined' && chrome.tabs?.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = tabs?.[0]?.url || 'https://mail.google.com';
        setCurrentUrl(url);
        scanUrlTarget(url);
      });
    } else {
      const url = 'https://mail.google.com';
      setCurrentUrl(url);
      scanUrlTarget(url);
    }
  };
  const scanUrlTarget = async (url) => {
    if (!url || url.startsWith('chrome://') || url.startsWith('about:')) {
      setScanResult({
        risk_level: 'safe',
        safety_score: 100,
        markers: [{ id: 'internal_browser', title: 'Browser Internal Page', description: 'Standard secure internal browser page.', severity: 'safe' }]
      });
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${backendUrl}/api/scan-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (res.ok) {
        setScanResult(await res.json());
        return;
      }
      throw new Error('Backend scan failed');
    } catch {
      const isHttps = url.startsWith('https://');
      setScanResult({
        risk_level: isHttps ? 'safe' : 'danger',
        safety_score: isHttps ? 85 : 30,
        markers: isHttps
          ? [{ id: 'verified_https', title: 'TLS/HTTPS Secure Connection', description: 'Encrypted channel active.', severity: 'safe' }]
          : [{ id: 'insecure_http', title: 'Unencrypted HTTP', description: 'Data transmitted without encryption.', severity: 'danger' }]
      });
    } finally {
      setLoading(false);
    }
  };

  // ── Google OAuth ──────────────────────────────────────────────────────────

  /**
   * Try to silently restore the user's session without showing a popup.
   * This runs every time the extension popup opens.
   */
  const tryRestoreSession = async () => {
    if (googleUser) {
      // User was previously signed in — try to silently get a fresh token
      const { getTokenSilent } = await import('./gmailApi');
      const tok = await getTokenSilent();
      if (tok) {
        setAccessToken(tok);
      } else {
        // Token is gone (user signed out from Chrome or revoked) — clear local state
        setGoogleUser(null);
        setAccessToken(null);
        localStorage.removeItem('sentinel_google_user');
      }
    }
  };

  /**
   * Sign in interactively. Shows the Google account chooser if needed.
   */
  const handleGoogleSignIn = async () => {
    setAuthLoading(true);
    try {
      const tok = await getToken(true);
      setAccessToken(tok);
      const profile = await fetchUserProfile(tok);
      setGoogleUser(profile);
      localStorage.setItem('sentinel_google_user', JSON.stringify(profile));
    } catch (err) {
      console.warn('[Sentinel AI] Sign-in failed:', err.message);
      alert(`Google Sign-In failed: ${err.message}\n\nMake sure your OAuth Client ID is set in manifest.json and the extension is listed in the Google Cloud Console.`);
    } finally {
      setAuthLoading(false);
    }
  };

  /**
   * Sign out: revoke token and clear all stored user data.
   */
  const handleGoogleSignOut = async () => {
    if (accessToken) {
      await revokeToken(accessToken);
    }
    setGoogleUser(null);
    setAccessToken(null);
    localStorage.removeItem('sentinel_google_user');
  };

  // ── Settings helpers ──────────────────────────────────────────────────────

  const toggleTheme = () => setTheme(prev => prev === 'cold' ? 'warm' : 'cold');
  const toggleMode = () => setMode(prev => prev === 'dark' ? 'light' : 'dark');

  const updateSettingField = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      chrome.storage.local.set({ [`sentinel_${key}`]: value });
    }
  };

  return (
    <div className="app-container">
      <Header
        theme={theme}
        mode={mode}
        onToggleTheme={toggleTheme}
        onToggleMode={toggleMode}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenHistory={() => setIsHistoryOpen(true)}
        backendOnline={backendOnline}
      />

      <nav className="nav-tabs" ref={navRef}>
        <div className="nav-indicator" style={pillStyle} />
        {TABS.map(tab => (
          <button
            key={tab.id}
            className={`nav-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.icon}{tab.label}
          </button>
        ))}
      </nav>

      <main className="content-area">
        <div key={activeTab} className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {activeTab === 'overview' && (
            <ShieldStatus
              currentUrl={currentUrl}
              scanResult={scanResult}
              loading={loading}
              theme={theme}
              mode={mode}
              onRescan={() => scanUrlTarget(currentUrl)}
            />
          )}
          {activeTab === 'email' && (
            <EmailScannerTab
              theme={theme}
              mode={mode}
              backendUrl={backendUrl}
              googleUser={googleUser}
              accessToken={accessToken}
              onSignIn={handleGoogleSignIn}
              authLoading={authLoading}
            />
          )}
          {activeTab === 'privacy' && (
            <PrivacyGuardTab
              theme={theme}
              mode={mode}
              backendUrl={backendUrl}
            />
          )}
        </div>
      </main>

      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        theme={theme}
        setTheme={setTheme}
        mode={mode}
        setMode={setMode}
        settings={settings}
        updateSettings={updateSettingField}
        backendUrl={backendUrl}
        setBackendUrl={setBackendUrl}
        backendOnline={backendOnline}
        checkBackendHealth={checkBackendHealth}
        googleUser={googleUser}
        authLoading={authLoading}
        onSignIn={handleGoogleSignIn}
        onSignOut={handleGoogleSignOut}
      />

      <HistoryModal
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        backendUrl={backendUrl}
        backendOnline={backendOnline}
      />
    </div>
  );
}
