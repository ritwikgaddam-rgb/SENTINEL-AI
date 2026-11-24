import React, { useEffect, useState } from 'react';
import { localApi } from '../localApi';

const LABELS = {
  emails: 'Email addresses', phone_numbers: 'Phones', aadhaar_numbers: 'Aadhaar', addresses: 'Addresses',
  postal_codes: 'Postal codes', ssn_numbers: 'SSNs', bank_accounts: 'Bank accounts', ifsc_codes: 'IFSC',
  iban_numbers: 'IBAN', card_numbers: 'Payment cards', pan_numbers: 'PAN', passport_numbers: 'Passports',
  upi_ids: 'UPI IDs', passwords: 'Passwords', api_keys: 'API keys', auth_tokens: 'Authentication tokens',
};

export default function PrivacyGuardTab({ backendUrl }) {
  const [inputText, setInputText] = useState('');
  const [approved, setApproved] = useState([]);
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState('');
  const [editing, setEditing] = useState(false);

  async function analyze(text, review, preview, signal) {
    const response = await localApi(backendUrl, '/api/privacy-redact', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, signal,
      body: JSON.stringify({ text, approved: review, preview }),
    });
    if (!response.ok) throw new Error('Local assessment failed');
    return response.json();
  }

  useEffect(() => {
    if (!inputText.trim()) {
      setEditing(false);
      return;
    }
    setEditing(true);
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const next = await analyze(inputText, approved, true, controller.signal);
        if (!controller.signal.aborted) setResult(next);
      } catch {
        if (!controller.signal.aborted) setStatus('Local privacy analysis is unavailable.');
      } finally {
        if (!controller.signal.aborted) setEditing(false);
      }
    }, 220);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [inputText, approved, backendUrl]);

  function change(text) {
    setInputText(text);
    setApproved([]);
    setResult(null);
    setStatus('');
  }

  async function copy() {
    try {
      const next = await analyze(inputText, approved, false);
      await navigator.clipboard.writeText(next.redacted_text);
      setStatus('Redacted text copied.');
    } catch {
      setStatus('Copy failed. The preview remains available.');
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <section className="card-section">
        <div className="card-title">
          <span>Identity redactor</span>
          <button type="button" className="btn-secondary" onClick={() => change('Email: demo@example.org\nPhone: +1 202-555-0100\nOrder ID: 9876543210\nApt: 25 Cedar Street')}>
            Insert sample
          </button>
        </div>
        <textarea className="textarea-clean" aria-label="Text to redact" rows={4} maxLength={40000}
          placeholder="Paste text for local redaction" value={inputText} onChange={event => change(event.target.value)} />
      </section>
      {result && <section className="card-section">
        <div className="card-title">{result.total_redacted} redacted</div>
        <div className="privacy-counters">
          {Object.entries(result.counts).filter(([, count]) => count > 0).map(([category, count]) =>
            <div className="counter-box" key={category}><div className="counter-num">{count}</div>
              <div className="counter-label">{LABELS[category]}</div></div>)}
        </div>
        {result.review.length > 0 && <div>
          <p>Review possible matches before copying.</p>
          {result.review.map(hit => <label key={hit.id} style={{ display: 'block' }}>
            <input type="checkbox" checked={approved.includes(hit.id)} onChange={event => {
              setStatus('');
              setApproved(items => event.target.checked ? [...items, hit.id] : items.filter(id => id !== hit.id));
            }} /> {LABELS[hit.category]} · <mark>{hit.excerpt}</mark>
          </label>)}
        </div>}
        <textarea className="textarea-clean" aria-label="Redacted preview" readOnly rows={4} value={result.redacted_text} />
        <button type="button" className="btn-primary" disabled={editing} onClick={copy}>Copy redacted text</button>
      </section>}
      {(status || editing) && <p role="status">{editing ? 'Checking locally…' : status}</p>}
    </div>
  );
}
