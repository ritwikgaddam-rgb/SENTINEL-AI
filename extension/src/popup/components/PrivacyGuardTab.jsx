import React, { useEffect, useState } from 'react';

export default function PrivacyGuardTab({ theme, mode, backendUrl }) {
  const [inputText, setInputText] = useState("");
  const [copied, setCopied] = useState(false);

  const [analysis, setAnalysis] = useState(null);
  const [failed, setFailed] = useState(null);
  const report = analysis?.input === inputText && analysis.backend === backendUrl ? analysis.data : null;
  const counts = report?.counts || {};
  const totalDetected = report?.total_redacted ?? 0;
  const categorySummary = [...new Set(report?.findings?.map(item => item.replacement) || [])].join(', ');

  useEffect(() => {
    if (!inputText.trim()) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const response = await fetch(backendUrl + '/api/privacy-redact', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: inputText, preview: true }), signal: controller.signal
        });
        if (!response.ok) throw new Error('Local privacy analysis unavailable');
        const data = await response.json();
        if (!controller.signal.aborted) {
          setAnalysis({ input: inputText, backend: backendUrl, data });
          setFailed(null);
        }
      } catch {
        if (!controller.signal.aborted) setFailed(inputText);
      }
    }, 220);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [inputText, backendUrl]);

  const handleCopyRedacted = async () => {
    if (!report) return;
    await navigator.clipboard.writeText(report.redacted_text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    fetch(backendUrl + '/api/privacy-redact', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: inputText, context: 'clipboard' })
    }).catch(() => {});
  };

  const loadSampleData = () => {
    setInputText("Student profile: John Doe, Aadhaar: 2345 6789 0124, Phone: +91 9123456789, Personal Email: student@example.org. Please confirm receipt.");
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {/* Counters Pill */}
      <div className="card-section">
        <div className="card-title">
          <span>Privacy Shield Active</span>
          <span title={categorySummary} style={{ fontSize: '11px', color: 'var(--accent-color)', fontWeight: 600 }}>
            {totalDetected} items detected
          </span>
        </div>

        <div className="privacy-counters">
          <div className="counter-box">
            <div className="counter-num">{counts.aadhaar_numbers ?? 0}</div>
            <div className="counter-label">Aadhaar IDs</div>
          </div>
          <div className="counter-box">
            <div className="counter-num">{counts.phone_numbers ?? 0}</div>
            <div className="counter-label">Phone #</div>
          </div>
          <div className="counter-box">
            <div className="counter-num">{counts.emails ?? 0}</div>
            <div className="counter-label">Emails</div>
          </div>
        </div>
      </div>

      {/* Input / Redact Card */}
      <div className="card-section">
        <div className="card-title">
          <span>Live Identity Redactor</span>
          <button
            onClick={loadSampleData}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent-color)',
              fontSize: '11px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            Insert Sample
          </button>
        </div>

        <div className="input-group">
          <textarea
            className="textarea-clean"
            placeholder="Type or paste text to test real-time sensitive information masking..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            rows={3}
          />
        </div>

        {inputText && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px', textTransform: 'uppercase' }}>
              Safe Redacted Preview
            </div>
            <div style={{
              background: 'var(--surface-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '10px 12px',
              fontSize: '12px',
              color: 'var(--text-main)',
              lineHeight: 1.4,
              wordBreak: 'break-word',
              maxHeight: '120px',
              overflowY: 'auto'
            }}>
              {report?.redacted_text ?? (failed === inputText ? 'Local privacy analysis unavailable.' : 'Checking text…')}
            </div>

            <button
              className="btn-primary"
              style={{ width: '100%', marginTop: '10px' }}
              onClick={handleCopyRedacted}
              disabled={!report}
            >
              {copied ? (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" width="13" height="13">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Copied Redacted Text to Clipboard
                </span>
              ) : "Copy Safe Redacted Version"}
            </button>
          </div>
        )}
      </div>

      <div className="card-section" style={{ background: 'var(--surface-input)' }}>
        <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.4, display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="14" height="14" style={{ flexShrink: 0, marginTop: '2px', color: 'var(--accent-primary)' }}>
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="16" x2="12" y2="12" />
            <line x1="12" y1="8" x2="12.01" y2="8" />
          </svg>
          <span>
            <strong>Privacy Guard Note:</strong> Sentinel AI inspects inputs locally before transmission, shielding citizens from identity theft and unredacted PII exposure across form submissions and email drafts.
          </span>
        </p>
      </div>
    </div>
  );
}
