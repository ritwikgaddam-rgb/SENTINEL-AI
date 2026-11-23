import type { ScanType } from "./api";

// Each scanner has a small diagram drawn on the same measurement grid.
function Globe() {
  return (
    <g>
      <g transform="rotate(-19 160 65)" strokeWidth="1.25" fill="none">
        <circle cx="160" cy="65" r="35" fill="currentColor" fillOpacity=".07" />
        <ellipse cx="160" cy="65" rx="15" ry="35" />
        <ellipse cx="160" cy="65" rx="27" ry="35" opacity=".7" />
        <ellipse cx="160" cy="65" rx="35" ry="9" />
        <path d="M130 47q30 14 60 0M131 85q29-12 58 0M160 30v70" />
        <ellipse cx="160" cy="65" rx="51" ry="17" transform="rotate(-12 160 65)" strokeDasharray="72 5 18 3" />
      </g>
      <path d="M111 70H79l-9 9H48m150-25h32l9-9h26" opacity=".48" />
      <circle cx="47" cy="79" r="2" /><circle cx="265" cy="45" r="2" />
      <circle cx="202" cy="39" r="3" fill="currentColor" />
    </g>
  );
}

function Envelope() {
  return (
    <g>
      <g transform="translate(158 65) matrix(1 -.18 .26 .94 0 0)" strokeLinejoin="round">
        <path d="M-39-24h78v49h-78z" transform="translate(-8 10)" opacity=".32" />
        <path d="M-39-24h78v49h-78z" transform="translate(-4 5)" opacity=".55" />
        <rect x="-39" y="-24" width="78" height="49" rx="2" fill="#28221c" strokeWidth="1.7" />
        <path d="m-38-22 35 27q3 2 6 0l35-27M-38 24l26-24m50 24L13 0" strokeWidth="1.6" />
        <path d="M-28-33h57m-47-5h30" opacity=".45" />
      </g>
      <path d="M104 58H83l-8-8H47m170 18h18l8 8h25" opacity=".48" />
      <circle cx="46" cy="50" r="2" /><circle cx="268" cy="76" r="2" />
    </g>
  );
}

function Fingerprint() {
  return (
    <g strokeLinecap="round">
      <g transform="translate(160 65) rotate(13)" strokeWidth="1.7">
        <path d="M-27 13v-17a27 27 0 0 1 54 0v11m-53 14c5-6 5-15 5-24a21 21 0 0 1 42 0c0 17 2 21 6 24" />
        <path d="M-19 26c5-7 5-15 5-29a14 14 0 0 1 28 0c0 15 0 23 8 32m-35 2c5-9 6-18 6-34a7 7 0 0 1 14 0c0 15-1 26 9 36" />
        <path d="M0-4c0 13 .4 29-6 39m6-10q1 6 5 12m1-16q2 8 5 12M-31-14q6-19 24-22m10 0q18 2 26 16" />
      </g>
      <path d="M119 47v-16h17m48 0h17v16m0 35v16h-17m-48 0h-17V82" opacity=".65" />
      <path d="M108 66H80l-9 8H49m164-11h24l9-9h24" opacity=".45" />
      <circle cx="48" cy="74" r="2" /><circle cx="271" cy="54" r="2" />
    </g>
  );
}

export default function ScannerArt({ type }: { type: ScanType }) {
  return (
    <div className={'scanner-art art-' + type} aria-hidden="true">
      <svg viewBox="0 0 320 130" fill="none" stroke="currentColor">
        <path d="M20 14h5m-2.5-2.5v5M295 113h5m-2.5-2.5v5" opacity=".42" />
        <path d="M18 113h20m-20-3v6m5-4v3m5-3v3m5-3v3m5-5v6" opacity=".32" />
        {type === "url" ? <Globe /> : type === "email" ? <Envelope /> : <Fingerprint />}
      </svg>
    </div>
  );
}
