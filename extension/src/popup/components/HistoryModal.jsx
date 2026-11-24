import React, { useEffect, useState } from 'react';

export default function HistoryModal({ isOpen, onClose, backendUrl, backendOnline }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [fetchError, setFetchError] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  const fetchHistory = async () => {
    setLoading(true);
    setFetchError(false);
    try {
      const res = await fetch(`${backendUrl}/api/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      } else {
        setFetchError(true);
      }
    } catch {
      // Gracefully handle offline without throwing console error
      setFetchError(true);
      setHistory([]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content animate-slide-up">
        <div className="modal-header">
          <h3 className="modal-title">Security & Audit History</h3>
          <button className="icon-btn" onClick={onClose} title="Close History">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="14" height="14">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="settings-list">
          {loading && (
            <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-secondary)', fontSize: '12px' }}>
              Querying SQLite database...
            </div>
          )}

          {fetchError && !loading && (
            <div style={{
              padding: '16px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--surface-card)',
              border: '1px solid var(--border-subtle)',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'center', color: 'var(--text-muted)' }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" width="24" height="24">
                  <line x1="1" y1="1" x2="23" y2="23" />
                  <path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55" />
                  <path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39" />
                  <path d="M10.71 5.05A16 16 0 0 1 22.58 9" />
                  <path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88" />
                  <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
                  <line x1="12" y1="20" x2="12.01" y2="20" />
                </svg>
              </div>
              <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-main)' }}>
                Backend Offline
              </div>
              <p style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                Start the backend in your terminal with <code>./start_backend.sh</code> on Mac/Linux or <code>start_backend.bat</code> on Windows to sync live threat history with the SQLite database.
              </p>
              <button
                className="btn-secondary"
                style={{ alignSelf: 'center', marginTop: '4px', height: '28px', fontSize: '11px', paddingLeft: '5px', paddingRight: '5px' }}
                onClick={fetchHistory}
              >
                Retry Connection
              </button>
            </div>
          )}

          {!loading && !fetchError && history.length === 0 && (
            <div style={{ textAlign: 'center', padding: '30px 10px', color: 'var(--text-secondary)', fontSize: '12.5px' }}>
              No threat detections logged yet. Scans from the extension and Gmail guardian will automatically appear here.
            </div>
          )}

          {!loading && !fetchError && history.map((item) => (
            <div key={item.id} className="marker-item animate-fade-in" style={{ gap: '4px' }}>
              <div className="marker-header">
                <span className="marker-badge" style={{
                  background: item.scan_type === 'url' ? 'var(--color-info-bg)' : 'var(--accent-glow-soft)',
                  color: item.scan_type === 'url' ? 'var(--color-info)' : 'var(--accent-color)'
                }}>
                  {item.scan_type.toUpperCase()}
                </span>
                <span className={`marker-badge ${item.risk_level}`}>
                  {item.risk_level}
                </span>
              </div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {item.target_preview}
              </div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-secondary)' }}>
                {new Date(item.created_at).toLocaleString()} • {Number.isFinite(item.risk_score) ? "Risk Score: " + item.risk_score + "%" : "Score unavailable"}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
