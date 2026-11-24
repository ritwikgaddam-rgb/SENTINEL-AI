import React, { useEffect, useState } from 'react';
import { requestLocal } from '../localApi';

export default function ThreatReview({ backendUrl }) {
  const [collection, setCollection] = useState(null);
  const [rows, setRows] = useState([]);
  const [stats, setStats] = useState({});
  const [kind, setKind] = useState('');
  const [filter, setFilter] = useState('');
  const [status, setStatus] = useState('');
  const [retention, setRetention] = useState(90);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const query = new URLSearchParams();
    if (kind) query.set('kind', kind);
    if (filter) query.set('status', filter);
    const [config, result] = await Promise.all([
      requestLocal(backendUrl, '/api/threats/settings'),
      requestLocal(backendUrl, '/api/threats?' + query),
    ]);
    setCollection(config);
    setRetention(config.retention_days);
    setRows(result.samples);
    setStats(result.counts);
  }

  useEffect(() => {
    refresh().catch(() => setStatus('Local threat review is unavailable.'));
  }, [backendUrl, kind, filter]);

  async function change(path, body, message) {
    setBusy(true);
    try {
      const response = await requestLocal(backendUrl, path, body);
      await refresh();
      setStatus(typeof message === 'function' ? message(response) : message);
    } catch (error) { setStatus(error.message); }
    finally { setBusy(false); }
  }

  async function download() {
    try {
      const result = await requestLocal(backendUrl, '/api/threats/export');
      const href = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = href;
      a.download = 'sentinel-approved-features.json';
      a.click();
      setTimeout(() => URL.revokeObjectURL(href), 1000);
      setStatus(`${result.samples.length} approved feature rows exported.`);
    } catch (error) { setStatus(error.message); }
  }

  return <section className="card-section">
    <div className="card-title">Threat review</div>
    <p>Collection is off by default. An enabled collection only accepts manual opt-in scans and stores numeric features.</p>
    <label style={{ display: 'block' }}>
      <input type="checkbox" checked={collection?.enabled ?? false} disabled={!collection || busy}
        onChange={event => change('/api/threats/settings', { enabled: event.target.checked }, 'Collection preference saved.')} />
      Enable local feature collection
    </label>
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBlock: 8 }}>
      <label>Retention days <input type="number" min="1" max="3650" value={retention}
        onChange={event => setRetention(event.target.value)} style={{ width: 65 }} /></label>
      <button className="btn-secondary" disabled={busy} onClick={() => change('/api/threats/settings',
        { retention_days: Number(retention) }, 'Retention saved.')}>Save retention</button>
      <button className="btn-secondary" disabled={busy} onClick={() => {
        if (window.confirm('Delete feature samples past the saved retention period?')) {
          change('/api/threats/prune', {}, result => `${result.deleted} expired sample(s) deleted.`);
        }
      }}>Delete expired</button>
      <button className="btn-secondary" onClick={download}>Export approved</button>
    </div>
    <div style={{ display: 'flex', gap: 6 }}>
      <select aria-label="Threat type" value={kind} onChange={event => setKind(event.target.value)}>
        <option value="">All types</option>
        <option value="email">Email</option><option value="url">URL</option><option value="webpage">Webpage</option>
      </select>
      <select aria-label="Review status" value={filter} onChange={event => setFilter(event.target.value)}>
        <option value="">All statuses</option>
        {['pending', 'confirmed_phishing', 'confirmed_legitimate', 'uncertain', 'rejected', 'approved'].map(value =>
          <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}
      </select>
    </div>
    <p>{Object.entries(stats).map(([key, value]) => `${key.replaceAll('_', ' ')} ${value}`).join(' · ') || 'No samples yet.'}</p>
    {rows.map(sample => <div className="marker-item" key={sample.id}>
      <strong>{sample.kind} #{sample.id} · {sample.status.replaceAll('_', ' ')}</strong>
      <span>Assessment: {sample.assessment}{sample.label ? ` · Reviewed: ${sample.label}` : ''}</span>
      <details><summary>Derived features</summary><p>{Object.entries(sample.features).map(([key, value]) => `${key}: ${value}`).join(', ')}</p></details>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {['phishing', 'legitimate', 'uncertain', 'rejected', 'approve', 'delete'].map(action => <button
          className="btn-secondary" key={action} disabled={busy || (action === 'approve' && !sample.status.startsWith('confirmed_'))}
          onClick={() => {
            if (action === 'delete' && !window.confirm('Delete this feature sample?')) return;
            change('/api/threats/review', { id: sample.id, action }, 'Review updated.');
          }}>{action}</button>)}
      </div>
    </div>)}
    {status && <p role="status">{status}</p>}
  </section>;
}
