import React from 'react';

export default function LogoLoader({ text = "Analyzing Security...", theme = "cold", mode = "dark", size = 48 }) {
  // Select rotating logo based on theme and mode
  let logoSrc = "logos/SentinelAILogoIconOnlySentinel(Purple).svg";

  if (theme === "warm") {
    logoSrc = "logos/SentinelAILogoIcon-SentinelOnly(Orange).svg";
  }

  return (
    <div className="loader-container">
      <img
        src={logoSrc}
        alt="Sentinel AI Loading"
        className="loader-logo sentinel-spinner"
        style={{ height: `${size}px`, width: 'auto' }}
      />
      {text && <span className="loader-text">{text}</span>}
    </div>
  );
}
