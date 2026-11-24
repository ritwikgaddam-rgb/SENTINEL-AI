import React from 'react';
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

  const riskLevel = scanResult?.risk_level || "unknown";
  const safetyScore = scanResult?.safety_score;
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
              {riskLevel === 'safe' ? 'No clear indicators' : riskLevel === 'suspicious' ? 'Caution Advised' : riskLevel === 'danger' ? 'Phishing Threat' : 'No score'}
            </span>
            <span className="score-pill" title="Sentinel AI screening score">
              {Number.isFinite(safetyScore) ? safetyScore + '% Safe' : 'Score unavailable'}
            </span>
          </div>

          <h3 className="status-title" title={currentUrl || "Active Tab"}>
            {currentUrl ? new URL(currentUrl).hostname || currentUrl : "Browser Protected"}
          </h3>
          <p className="status-desc">
            {scanResult?.explanation || scanResult?.assessment || 'Waiting for a web address.'}
          </p>
        </div>
      </div>

      {/* Quick Action Bar */}
      <div style={{ display: 'flex', gap: '8px' }}>
        <button
          className="btn-primary"
          style={{ flex: 1 }}
          onClick={onRescan}
          disabled={loading}
        >
          {loading ? 'Scanning Destination...' : 'Scan Active Page'}
        </button>
      </div>

      {/* Threat Markers */}
      <MarkersCard
        markers={markers}
        title="URL Threat Markers & Heuristics"
      />
    </div>
  );
}
