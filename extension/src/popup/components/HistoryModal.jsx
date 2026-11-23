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
            ✕
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
              <span style={{ fontSize: '20px' }}>🔌</span>
              <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-main)' }}>
                Backend Offline
              </div>
              <p style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                Start the backend in your terminal with <code>./start_backend.sh</code> to sync live threat history with the SQLite database.
              </p>
              <button
                className="btn-secondary"
                style={{ alignSelf: 'center', marginTop: '4px', height: '28px', fontSize: '11px' }}
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
                {new Date(item.created_at).toLocaleString()} • Risk Score: {item.confidence}%
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
