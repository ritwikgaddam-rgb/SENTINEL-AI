import React, { useState } from 'react';
import MarkersCard from './MarkersCard';

export default function ShieldStatus({
  currentUrl,
  scanResult,
  loading,
  theme,
  mode,
  onRescan
}) {
  // Select shield logo according to theme and mode
  let shieldSrc = "logos/SentinelAILogoIcon(Purple).svg";

  if (theme === "warm") {
    if (mode === "light") {
      shieldSrc = "logos/SentinelAILogoIconAlternate(LightMode Orange).svg";
    } else {
      shieldSrc = "logos/SentinelAILogoIcon(Orange).svg";
    }
  } else {
    if (mode === "light") {
      shieldSrc = "logos/SentinelAILogoIconAlternate(LightModePurple).svg";
    } else {
      shieldSrc = "logos/SentinelAILogoIcon(Purple).svg";
    }
  }

  const riskLevel = scanResult?.risk_level === 'suspicious' ? 'suspicious' : 'uncertain';
  const [address, setAddress] = useState('');
  const [collectSample, setCollectSample] = useState(false);
  let host = 'Active tab';
  try { host = new URL(currentUrl).hostname || host; } catch { /* A tab may have no accessible URL. */ }
  const markers = scanResult?.markers || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {/* Hero Status Card */}
      <div className="status-hero-card">
        <div className={`shield-emblem-wrap ${loading ? 'sentinel-spinner' : 'sentinel-pulse'}`}>
          <img
            src={shieldSrc}
            alt="Sentinel Shield"
            className="shield-emblem-img"
          />
        </div>

        <div className="status-info">
          <div className="status-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2px' }}>
            <span className={`status-badge ${riskLevel}`}>
              {loading ? 'Checking address…' : scanResult?.assessment || 'Ready to check address'}
            </span>
          </div>
          <h3 className="status-title">{host}</h3>
          <p className="status-desc">{scanResult?.explanation || 'Check the address structure.'}
          </p>
        </div>
      </div>

      {/* Quick Action Bar */}
      <div style={{ display: 'flex', gap: '8px' }}>
        <input className="input-clean" aria-label="Website address" placeholder={host === 'Active tab' ? 'https://example.org' : host}
          value={address} onChange={event => setAddress(event.target.value)} maxLength={2083} />
        <button
          className="btn-primary"
          style={{ flex: 1 }}
          onClick={() => onRescan(address.trim() || currentUrl, collectSample)}
          disabled={loading || !(address.trim() || currentUrl)}
        >
          {loading ? 'Scanning Destination...' : 'Scan active address'}
        </button>
      </div>

      <label><input type="checkbox" checked={collectSample} onChange={event => setCollectSample(event.target.checked)} /> Save derived features from the next address scan</label>
      {scanResult?.sample_id && <p role="status">Features saved for review.</p>}
      {scanResult?.model_observation && <details className="card-section"><summary>Experimental structure model</summary>
        <p>{scanResult.model_observation.message} This observation does not determine the assessment.</p>
      </details>}
      {/* Threat Markers */}
      <MarkersCard
        markers={markers}
        title="URL Threat Markers & Heuristics"
      />
    </div>
  );
}
