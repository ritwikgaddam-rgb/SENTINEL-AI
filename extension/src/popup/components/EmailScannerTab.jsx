import React, { useState } from 'react';
import MarkersCard from './MarkersCard';
import LogoLoader from './LogoLoader';

export default function EmailScannerTab({ theme, mode, backendUrl }) {
  const [emailText, setEmailText] = useState("");
  const [sender, setSender] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const handleScan = async () => {
    if (!emailText.trim()) return;
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(`${backendUrl}/api/scan-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: emailText,
          sender: sender.trim()
        })
      });

      if (response.ok) {
        const data = await response.json();
        setResult(data);
      } else {
        throw new Error("Backend error");
      }
    } catch (e) {
      // Local fallback heuristic scanner if backend is temporarily unreachable
      const textLower = emailText.toLowerCase();
      const hasUrgency = /urgent|suspended|password|verify|immediately|within \d+ hours/.test(textLower);
      const aadhaarMatches = emailText.match(/(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)/g) || [];
      const phoneMatches = emailText.match(/(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)/g) || [];
      const emailMatches = emailText.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || [];

      const fallbackMarkers = [];
      if (hasUrgency) {
        fallbackMarkers.push({
          id: "urgency_fallback",
          title: "High-Pressure Psychological Trigger",
          description: "Detected urgent phrasing designed to induce rushed decision-making.",
          severity: "high"
        });
      }
      if (aadhaarMatches.length > 0) {
        fallbackMarkers.push({
          id: "aadhaar_fallback",
          title: "Unprotected Aadhaar Number Found",
          description: `Message exposes ${aadhaarMatches.length} Indian national ID (Aadhaar) number(s).`,
          severity: "danger"
        });
      }

      setResult({
        risk_score: hasUrgency || aadhaarMatches.length > 0 ? 82.0 : 15.0,
        safety_score: hasUrgency || aadhaarMatches.length > 0 ? 18.0 : 85.0,
        risk_level: hasUrgency || aadhaarMatches.length > 0 ? "danger" : "safe",
        markers: fallbackMarkers,
        privacy: {
          emails: emailMatches,
          phone_numbers: phoneMatches,
          aadhaar_numbers: aadhaarMatches
        },
        private_items_count: aadhaarMatches.length + phoneMatches.length + emailMatches.length
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRedactAndCopy = async () => {
    let cleaned = emailText;
    if (result?.privacy) {
      for (const a of result.privacy.aadhaar_numbers || []) cleaned = cleaned.replace(a, "[AADHAAR]");
      for (const p of result.privacy.phone_numbers || []) cleaned = cleaned.replace(p, "[PHONE]");
      for (const e of result.privacy.emails || []) cleaned = cleaned.replace(e, "[EMAIL]");
    }
    await navigator.clipboard.writeText(cleaned);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const loadSamplePhish = () => {
    setSender("security-alert@paypal-auth-verify.xyz");
    setEmailText("URGENT: Your account has been suspended due to unauthorized access. Please verify your identity and confirm your Aadhaar number 4589 1234 5678 and phone +91 9876543210 immediately to restore access within 24 hours.");
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div className="card-section">
        <div className="card-title">
          <span>Email & Text Phishing Scanner</span>
          <button
            onClick={loadSamplePhish}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent-color)',
              fontSize: '11px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            Load Sample Phish
          </button>
        </div>

        <div className="input-group">
          <input
            type="text"
            className="input-clean"
            placeholder="Sender address (optional, e.g. support@bank.com)"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
          />
          <textarea
            className="textarea-clean"
            placeholder="Paste email text, suspicious message, or draft content here..."
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
          />

          <button
            className="btn-primary"
            onClick={handleScan}
            disabled={loading || !emailText.trim()}
          >
            {loading ? "Analyzing Message..." : "Analyze Email for Phishing & Leaks"}
          </button>
        </div>
      </div>

      {loading && (
        <LogoLoader
          theme={theme}
          mode={mode}
          text="Deep Phishing Analysis..."
        />
      )}

      {result && !loading && (
        <>
          {/* Risk Overview Card */}
          <div className="status-hero-card">
            <div className="shield-emblem-wrap">
              <img
                src={theme === 'warm' ? "logos/SentinelAILogoIcon-SentinelOnly(Orange).svg" : "logos/SentinelAILogoIconOnlySentinel(Purple).svg"}
                alt="Emblem"
                className="shield-emblem-img"
              />
            </div>
            <div className="status-info">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span className={`status-badge ${result.risk_level}`}>
                  {result.risk_level === 'danger' ? 'Phishing Threat' : result.risk_level === 'suspicious' ? 'Suspicious Content' : 'Legitimate'}
                </span>
                <span className="score-pill">{result.safety_score}% Safe</span>
              </div>
              <h4 className="status-title">
                {result.risk_level === 'danger' ? 'High Risk Detected' : 'Content Appears Safe'}
              </h4>
              <p className="status-desc">
                {result.private_items_count > 0
                  ? `Identified ${result.private_items_count} private identity data points.`
                  : 'No credential or identity exposure found.'}
              </p>
            </div>
          </div>

          {/* Privacy Redaction Bar if sensitive items found */}
          {result.private_items_count > 0 && (
            <div className="card-section" style={{ background: 'var(--surface-input)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontWeight: 600 }}>
                  🛡️ {result.private_items_count} Sensitive Items Detected
                </span>
                <button
                  className="btn-secondary"
                  style={{ height: '28px', fontSize: '11px', padding: '0 8px' }}
                  onClick={handleRedactAndCopy}
                >
                  {copied ? '✓ Copied Redacted Text' : 'Redact & Copy'}
                </button>
              </div>
            </div>
          )}

          {/* Markers List */}
          <MarkersCard
            markers={result.markers}
            title="Suspicious Email Markers & Cues"
          />
        </>
      )}
    </div>
  );
}
