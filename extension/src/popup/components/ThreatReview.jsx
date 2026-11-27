import React, { useEffect, useState } from 'react';
import { localApi } from '../localApi';
import { formatRiskIndex } from '../../inference/scoreLabel.mjs';

const PAGE_SIZE = 100;
const actions = {
  phishing: 'Confirm phishing',
  legitimate: 'Confirm legitimate',
  uncertain: 'Mark uncertain',
  rejected: 'Reject',
  approve: 'Approve for training',
  delete: 'Delete sample',
};

async function request(backendUrl, path, body) {
  const options = body ? {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)} : {};
  const response = await localApi(backendUrl, '/api/threats' + path, options);
  if (!response.ok) throw new Error('Threat request failed');
  return response.json();
}

export default function ThreatReview({ backendUrl }) {
  const [data, setData] = useState(null);
  const [offset, setOffset] = useState(0);
  const [selection, setSelection] = useState({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');

  async function update(page = offset, operation) {
    setBusy(true);
    setMessage('');
    try {
      if (operation) await operation();
      const [settings, queue] = await Promise.all([
        request(backendUrl, '/settings'),
        request(backendUrl, '?offset=' + page),
      ]);
      setData({settings, ...queue});
      setOffset(page);
    } catch {
      setData(null);
      setMessage('Threat collection unavailable. Check the local backend and its threat database.');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { update(0); }, [backendUrl]);

  function review(sample) {
    const action = selection[sample.id];
    if (!action || (action === 'delete' && !window.confirm('Delete this threat sample?'))) return;
    update(0, async () => {
      await request(backendUrl, '/review', {id: sample.id, action});
      setSelection({});
    });
  }

  async function exportSamples() {
    setBusy(true);
    setMessage('');
    try {
      const report = await request(backendUrl, '/export');
      const href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
      const link = document.createElement('a');
      link.href = href;
      link.download = 'sentinelai-approved-threats.json';
      link.click();
      setTimeout(() => URL.revokeObjectURL(href), 1000);
      setMessage('Approved training export downloaded.');
    } catch {
      setMessage('Export unavailable. Check the local backend and retry.');
    } finally {
      setBusy(false);
    }
  }

  const total = data ? Object.values(data.counts).reduce((sum, count) => sum + count, 0) : 0;
  return (
    <section className="card-section" aria-label="Threat review">
      <div className="card-title">Threat review</div>
      <p className="setting-desc">
        Collect numeric features, risk indices and warning categories from suspicious scans, including opened Gmail messages.
        Automatic collection saves no message text, private links or attachments.
      </p>
      {busy && <p className="setting-desc" role="status">Updating the threat queue…</p>}
      {message && <p className="setting-desc" role="status">{message}</p>}
      {!data && !busy && <button className="btn-secondary" onClick={() => update(0)}>Retry threat connection</button>}
      {data && (
        <div className="settings-list">
          <div className="setting-row">
            <span className="setting-label">Automatic collection</span>
            <label className="switch">
              <input type="checkbox" aria-label="Automatic threat collection" checked={data.settings.enabled}
                disabled={busy} onChange={event => {
                  const enabled = event.target.checked;
                  update(0, () => request(backendUrl, '/settings', {enabled}));
                }} />
              <span className="slider" />
            </label>
          </div>
          <p className="setting-desc">
            {total} collected · {data.counts.pending ?? 0} pending · {data.label_counts.phishing ?? 0} confirmed phishing
            {' · '}{data.label_counts.legitimate ?? 0} confirmed legitimate · {data.counts.approved ?? 0} approved
          </p>
          <button className="btn-secondary" disabled={busy || !data.counts.approved} onClick={exportSamples}>Export approved samples</button>
          {!data.samples.length && <p className="setting-desc">No threat samples on this page.</p>}
          {data.samples.map(sample => (
            <div className="marker-item" key={sample.id}>
              <div className="marker-header">
                <strong>{sample.kind}</strong>
                <span className="marker-badge">{sample.status.replaceAll('_', ' ')}</span>
              </div>
              <div className="setting-desc">
                {new Date(sample.created_at.replace(' ', 'T') + 'Z').toLocaleString()} · {formatRiskIndex(sample.risk_index)}
                {sample.label ? ' · ' + sample.label : ''}
              </div>
              <select className="input-clean" aria-label={'Review sample ' + sample.id} disabled={busy}
                value={selection[sample.id] || ''}
                onChange={event => setSelection({...selection, [sample.id]: event.target.value})}>
                <option value="">Choose an action</option>
                {Object.entries(actions).map(([value, label]) => (
                  <option key={value} value={value}
                    disabled={value === 'approve' && !['confirmed_phishing', 'confirmed_legitimate'].includes(sample.status)}>
                    {label}
                  </option>
                ))}
              </select>
              <button className="btn-secondary" disabled={busy || !selection[sample.id]} onClick={() => review(sample)}>Apply review</button>
            </div>
          ))}
          {offset > 0 && <button className="btn-secondary" disabled={busy} onClick={() => update(offset - PAGE_SIZE)}>Previous samples</button>}
          {offset + PAGE_SIZE < total && <button className="btn-secondary" disabled={busy} onClick={() => update(offset + PAGE_SIZE)}>More samples</button>}
        </div>
      )}
    </section>
  );
}
