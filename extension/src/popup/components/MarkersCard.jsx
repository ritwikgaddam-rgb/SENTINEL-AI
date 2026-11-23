import React from 'react';

export default function MarkersCard({ markers = [], title = "Threat Analysis & Markers" }) {
  if (!markers || markers.length === 0) {
    return null;
  }

  return (
    <div className="card-section">
      <div className="card-title">
        <span>{title}</span>
        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
          {markers.length} {markers.length === 1 ? 'indicator' : 'indicators'}
        </span>
      </div>

      <div className="markers-list">
        {markers.map((marker, index) => {
          const severity = marker.severity || 'medium';
          return (
            <div key={marker.id || index} className={`marker-item ${severity}`}>
              <div className="marker-header">
                <span className="marker-title">{marker.title}</span>
                <span className={`marker-badge ${severity}`}>
                  {severity}
                </span>
              </div>
              <p className="marker-desc">{marker.description}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
