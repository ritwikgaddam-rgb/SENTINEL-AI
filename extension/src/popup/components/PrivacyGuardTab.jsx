import React, { useState } from 'react';

export default function PrivacyGuardTab({ theme, mode, backendUrl }) {
  const [inputText, setInputText] = useState("");
  const [copied, setCopied] = useState(false);

  // Live client-side regex matching using privacy_detector rules
  const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const phonePattern = /(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)/g;
  const aadhaarPattern = /(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)/g;

  const emailsFound = inputText.match(emailPattern) || [];
  const phonesFound = inputText.match(phonePattern) || [];
  const aadhaarFound = inputText.match(aadhaarPattern) || [];

  const totalDetected = emailsFound.length + phonesFound.length + aadhaarFound.length;

  const getRedactedText = () => {
    let text = inputText;
    text = text.replace(emailPattern, "[EMAIL]");
    text = text.replace(phonePattern, "[PHONE]");
    text = text.replace(aadhaarPattern, "[AADHAAR]");
    return text;
  };

  const handleCopyRedacted = async () => {
    const redacted = getRedactedText();
    await navigator.clipboard.writeText(redacted);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const loadSampleData = () => {
    setInputText("Student profile: John Doe, Aadhaar: 9876 5432 1098, Phone: +91 9123456789, Personal Email: john.student@gmail.com. Please confirm receipt.");
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {/* Counters Pill */}
      <div className="card-section">
        <div className="card-title">
          <span>Privacy Shield Active</span>
          <span style={{ fontSize: '11px', color: 'var(--accent-color)', fontWeight: 600 }}>
            {totalDetected} items detected
          </span>
        </div>

        <div className="privacy-counters">
          <div className="counter-box">
            <div className="counter-num">{aadhaarFound.length}</div>
            <div className="counter-label">Aadhaar IDs</div>
          </div>
          <div className="counter-box">
            <div className="counter-num">{phonesFound.length}</div>
            <div className="counter-label">Phone #</div>
          </div>
          <div className="counter-box">
            <div className="counter-num">{emailsFound.length}</div>
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
            placeholder="Type or paste text to test real-time Indian Aadhaar & Phone data masking..."
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
              {getRedactedText()}
            </div>

            <button
              className="btn-primary"
              style={{ width: '100%', marginTop: '10px' }}
              onClick={handleCopyRedacted}
            >
              {copied ? "✓ Copied Redacted Text to Clipboard" : "Copy Safe Redacted Version"}
            </button>
          </div>
        )}
      </div>

      <div className="card-section" style={{ background: 'var(--surface-input)' }}>
        <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
          💡 <strong>Privacy Guard Note:</strong> Sentinel AI inspects inputs locally before transmission, shielding citizens from identity theft and unredacted PII exposure across form submissions and email drafts.
        </p>
      </div>
    </div>
  );
}
