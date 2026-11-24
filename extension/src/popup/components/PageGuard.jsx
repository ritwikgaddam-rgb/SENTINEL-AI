import React, { useState } from 'react';
import { inspectActiveDocument } from '../../pageInspection';
import { requestLocal } from '../localApi';
import MarkersCard from './MarkersCard';

export default function PageGuard({ backendUrl }) {
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState('');
  const [watching, setWatching] = useState(false);
  const [collectSample, setCollectSample] = useState(false);
  const [busy, setBusy] = useState(false);
  const available = typeof chrome !== 'undefined' && Boolean(chrome.scripting);

  async function scan(action) {
    setBusy(true);
    setStatus('');
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id == null || !/^https?:\/\//i.test(tab.url || '')) throw new Error('Open a regular HTTP or HTTPS page first.');
      const [{ result: info }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id }, func: inspectActiveDocument, args: [action],
      });
      setWatching(info.watching);
      if (action === 'stop') {
        setStatus('Watching stopped for this page.');
      } else {
        const address = new URL(tab.url);
        const data = await requestLocal(backendUrl, '/api/scan-page', {
          url: address.origin + address.pathname, observations: info.observations,
          collect_sample: collectSample && action === 'scan',
        });
        setResult(data);
        if (collectSample) setStatus(data.sample_id ? 'Features saved for review.' : 'No new sample saved. Check collection settings.');
      }
    } catch (error) {
      setStatus(error.message || 'Webpage analysis is unavailable.');
    } finally {
      setBusy(false);
    }
  }

  return <section className="card-section">
    <div className="card-title">Webpage evidence</div>
    <p>Scan the active page for suspicious forms and dialogs. Watching applies to this document for up to 10 minutes.</p>
    {available ? <>
      <button type="button" className="btn-primary" disabled={busy} onClick={() => scan('scan')}>Scan webpage</button>
      <button type="button" className="btn-secondary" disabled={busy} onClick={() => scan('watch')}>Watch this page</button>
      <button type="button" className="btn-secondary" disabled={busy} onClick={() => scan('stop')}>Stop watching</button>
      <label style={{ display: 'block' }}><input type="checkbox" checked={collectSample} onChange={event => setCollectSample(event.target.checked)} /> Save derived features from the next manual scan</label>
      {watching && <p>Watching this document.</p>}
    </> : <p>Open the Chrome extension to scan the active document.</p>}
    {status && <p role="status">{status}</p>}
    {result && <div><strong>{result.assessment}</strong><p>{result.explanation}</p>
      {result.model_observation && <details><summary>Experimental address observation</summary><p>{result.model_observation.message}</p></details>}
      <details><summary>Observed page structure</summary>
        <ul>
          <li>{result.observations.credential_forms} form(s) with a visible password field</li>
          <li>{result.observations.payment_fields} payment field(s)</li>
          <li>{result.observations.overlays} visible dialog(s) or overlay(s)</li>
          <li>{result.observations.links} visible link(s), {result.observations.external_links} on another host</li>
          <li>{result.observations.buttons} visible button(s), {result.observations.iframes} visible frame(s)</li>
        </ul>
      </details>
      <MarkersCard markers={result.markers} title="Observed indicators" /></div>}
  </section>;
}
