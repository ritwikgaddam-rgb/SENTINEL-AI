import { useId, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertCircle, Globe2, LoaderCircle, LockKeyhole, Mail, ScanLine, ShieldAlert, ShieldCheck } from "lucide-react";
import { RiskBadge } from "./Activity.jsx";
import "./panels.css";

const percent = new Intl.NumberFormat(undefined, {
  style: "percent",
  maximumFractionDigits: 2,
});

const modes = {
  url: { name: "URL", title: "Check a website", icon: Globe2, limit: 2083 },
  email: { name: "Email text", title: "Check an email", icon: Mail, limit: 20000 },
};

function ScanResult({ result, scanning, error, kind }) {
  if (!result) {
    return (
      <div className="scan-result-empty" role={error ? "alert" : "status"}>
        <div className={error ? "scan-placeholder error" : "scan-placeholder"} aria-hidden="true">
          {scanning ? <LoaderCircle className="scan-spinner" size={24} /> : error ? <AlertCircle size={24} /> : <ScanLine size={24} />}
        </div>
        <h3>{scanning ? "Analyzing input" : error ? "Scan couldn’t finish" : "Waiting for a scan"}</h3>
        <p>
          {scanning ? "The local model is checking for phishing signals."
            : error || "The prediction and phishing probability will appear here."}
        </p>
      </div>
    );
  }

  if (result.prediction === "Insufficient information") {
    return (
      <div className="scan-result-empty" role="status">
        <div className="scan-placeholder" aria-hidden="true"><AlertCircle size={24} /></div>
        <h3>{result.prediction}</h3>
        <p>{result.reason ?? "The model could not assess this input reliably."}</p>
      </div>
    );
  }

  const flagged = result.prediction === "Phishing";
  const Icon = flagged ? ShieldAlert : ShieldCheck;
  const probability = result.phishing_probability;

  return (
    <div className="scan-result-content" role="status">
      <div className="scan-prediction">
        <span className={flagged ? "scan-prediction-icon flagged" : "scan-prediction-icon"}><Icon size={22} aria-hidden="true" /></span>
        <div>
          <span className="scan-result-label">Model prediction</span>
          <h3>{result.prediction}</h3>
        </div>
        <RiskBadge risk={result.risk_level} />
      </div>
      <div className="scan-probability">
        <div><span>Phishing probability</span><strong>{percent.format(probability)}</strong></div>
        <meter
          aria-label="Phishing probability"
          className={flagged ? "flagged" : ""}
          min={0}
          max={1}
          value={probability}
        >
          {percent.format(probability)}
        </meter>
      </div>
      <p className="scan-interpretation">
        {flagged
          ? "Review the " + (kind === "url" ? "address" : "email") + " before trusting it."
          : "The model found a low likelihood of phishing. Use your judgment with unfamiliar " + (kind === "url" ? "links." : "senders.")}
      </p>
    </div>
  );
}

export default function Scan({ native, onScan, initialKind = "url" }) {
  const field = useId();
  const [kind, setKind] = useState(initialKind === "email" ? "email" : "url");
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [scanning, setScanning] = useState(false);
  const urlScan = kind === "url";
  const mode = modes[kind];
  const ModeIcon = mode.icon;

  function edit(value) {
    setInput(value);
    setResult(null);
    setError("");
  }

  async function submit(event) {
    event.preventDefault();
    if (!native || scanning || !input.trim()) return;
    setResult(null);
    setError("");
    setScanning(true);

    try {
      const result = urlScan
        ? await invoke("scan_url", { url: input.trim() })
        : await invoke("scan_email", { text: input });
      setResult(result);
      onScan?.(result, kind);
    } catch (error) {
      setError(String(error));
    } finally {
      setScanning(false);
    }
  }

  return (
    <section className="scan-panel" aria-label="Manual phishing scanner">
      <div className="scan-toolbar">
        <div className="segmented" role="group" aria-label="Scan type">
          {Object.entries(modes).map(([key, option]) => {
            const Icon = option.icon;
            return (
              <button
                key={key}
                type="button"
                aria-pressed={kind === key}
                disabled={scanning}
                onClick={() => { if (kind !== key) { setKind(key); edit(""); } }}
              >
                <Icon size={15} aria-hidden="true" /> {option.name}
              </button>
            );
          })}
        </div>
      </div>

      <div className="scan-grid">
        <div className="card scan-card">
          <div className="scan-card-heading">
            <span className="scan-mode-icon"><ModeIcon size={18} aria-hidden="true" /></span>
            <h2>{mode.title}</h2>
          </div>
          <p className="scan-card-description">
            {urlScan ? "Analyze a web address without opening the linked site." : "Analyze the wording of a suspicious email or message."}
          </p>
          <form className="scan-form" onSubmit={submit}>
            <label htmlFor={field}>{urlScan ? "Website address" : "Email or message text"}</label>
            {urlScan ? (
              <input
                id={field}
                type="url"
                placeholder="https://example.org"
                value={input}
                onChange={(event) => edit(event.target.value)}
                maxLength={mode.limit}
                readOnly={scanning}
                autoCapitalize="off"
                spellCheck={false}
                required
              />
            ) : (
              <textarea
                id={field}
                rows={6}
                placeholder="Paste the email or message here"
                value={input}
                onChange={(event) => edit(event.target.value)}
                maxLength={mode.limit}
                readOnly={scanning}
                required
              />
            )}
            <div className="scan-form-actions">
              <button className="button primary" type="submit" disabled={!native || !input.trim() || scanning}>
                {scanning ? <LoaderCircle className="scan-spinner" size={15} aria-hidden="true" /> : <ScanLine size={15} aria-hidden="true" />}
                {scanning ? "Scanning…" : urlScan ? "Scan URL" : "Scan email"}
              </button>
              {input && <button className="button quiet" type="button" disabled={scanning} onClick={() => edit("")}>Clear</button>}
            </div>
          </form>
          <p className="scan-privacy-note">
            <LockKeyhole size={14} aria-hidden="true" /> History stores scan results only.
          </p>
        </div>
        <div className="card scan-card scan-result-card" aria-busy={scanning}>
          <div className="scan-card-heading"><h2>Scan result</h2></div>
          <ScanResult result={result} error={error} scanning={scanning} kind={kind} />
        </div>
      </div>
    </section>
  );
}
