import { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  Activity as ActivityIcon, ArrowRight, CircleAlert, Clock3, LayoutGrid, Link2,
  Mail, MessageSquare, ScanLine, Settings2, ShieldAlert, ShieldCheck,
} from "lucide-react";
import navyLogo from "../../assets/logos/SentinelAILogoFull.svg";
import emberLogo from "../../assets/logos/SentinelAILogoTotal-NoBG(Orange).svg";
import navyIcon from "../../assets/logos/SentinelAILogoIcon(Purple).svg";
import emberIcon from "../../assets/logos/SentinelAILogoIcon(Orange).svg";
import Activity from "./Activity.jsx";
import Scan from "./Scan.jsx";
import Settings, { MonitoringCard, useMessages } from "./MessagesAccess.jsx";
import "./style.css";

const native = isTauri();
const pages = [
  { id: "overview", title: "Overview", icon: LayoutGrid, description: "Review your local protection and recent scan activity." },
  { id: "activity", title: "Activity", icon: ActivityIcon, description: "Review results from your scanners and Apple Messages." },
  { id: "scan", title: "Scan", icon: ScanLine, description: "Check a link or pasted email with your local phishing model." },
  { id: "settings", title: "Settings", icon: Settings2, description: "Manage appearance, permissions, and local data." },
];
const sources = {
  url: ["URL scan", Link2],
  email: ["Email scan", Mail],
  privacy: ["Privacy scan", ShieldCheck],
  messages: ["Apple Messages", MessageSquare],
};
const shortTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function rememberTheme(value) {
  try { localStorage.setItem("sentinelai-theme", value); } catch { /* The theme still applies for this session. */ }
}

function savedTheme() {
  try { return ["ember", "maroon"].includes(localStorage.getItem("sentinelai-theme")) ? "ember" : "navy"; }
  catch { return "navy"; }
}

function probabilityFromFindings(findings) {
  const match = /([0-9]+(?:\.[0-9]+)?)% phishing probability$/.exec(findings ?? "");
  if (!match) return null;
  const probability = Number(match[1]) / 100;
  return probability >= 0 && probability <= 1 ? probability : null;
}

function combineHistory(apiItems, messages) {
  const results = apiItems.flatMap(item => {
    const source = sources[item.scan_type]?.[0];
    if (!source || !Number.isFinite(Date.parse(item.timestamp))) return [];
    return [{
      key: "api-" + item.id, source, kind: item.scan_type, time: item.timestamp,
      prediction: item.prediction, probability: probabilityFromFindings(item.findings), risk: item.risk_level,
    }];
  });
  for (const entry of messages) {
    if (!Number.isFinite(Date.parse(entry.detected_at))) continue;
    results.push({
      key: "message-" + entry.id, source: entry.source, kind: "messages", time: entry.detected_at,
      prediction: entry.prediction, probability: entry.phishing_probability,
      risk: entry.prediction === "Phishing" ? "High" : entry.prediction === "Legitimate" ? "Low" : null,
    });
  }
  return results.sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
}

function Overview({ backend, messages, totals, records, historyLoading, historyError, theme, navigate }) {
  const ready = backend.state === "connected";
  const checking = backend.state === "checking";
  const flagged = records.filter(record => record.prediction === "Phishing").slice(0, 3);
  const StatusIcon = ready ? ShieldCheck : checking ? Clock3 : CircleAlert;

  return (
    <div className="overview">
      <section className="protection" aria-label="Security status">
        <div className="protection-copy">
          <div className="hero-label"><StatusIcon size={16} /> Security status</div>
          <h2>{ready ? "Ready to scan" : checking ? "Checking local service…" : "Local service unavailable"}</h2>
          <p>{ready ? "Check links and email with the local model." : checking ? "Connecting to the SentinelAI engine on this Mac." : "Start the local FastAPI service to run phishing scans."}</p>
          <div className="hero-actions">
            {ready || checking ? <>
              <button type="button" className="button hero-button" onClick={() => navigate("scan", "url")}><Link2 size={15} /> Scan a URL</button>
              <button type="button" className="button hero-button" onClick={() => navigate("scan", "email")}><Mail size={15} /> Scan email</button>
            </> : <button type="button" className="button hero-button" onClick={() => navigate("settings")}><Settings2 size={15} /> Connection settings</button>}
          </div>
        </div>
        <div className="hero-art" aria-hidden="true">
          <div className="hero-ring ring-outer" />
          <div className="hero-ring ring-inner" />
          <img src={theme === "ember" ? emberIcon : navyIcon} alt="" />
        </div>
      </section>

      <section className="metrics-grid" aria-label="Scan totals">
        <Metric icon={ScanLine} label="Total scans" value={totals?.scans} note="Scanners and Messages" />
        <Metric icon={ShieldAlert} label="Flagged scans" value={totals?.flagged} note="Predicted to be phishing" danger />
      </section>

      <div className="overview-bottom">
        <section className="card recent-card" aria-labelledby="recent-title">
          <div className="recent-heading">
            <h2 id="recent-title">Recent suspicious activity</h2>
            <button type="button" className="button quiet text-button" onClick={() => navigate("activity", "flagged")}>View activity <ArrowRight size={14} /></button>
          </div>
          {flagged.length ? (
            <ul className="recent-list">
              {flagged.map(item => {
                const Icon = sources[item.kind][1];
                return <li key={item.key}>
                  <span className="icon-tile"><Icon size={17} /></span>
                  <span className="recent-detail"><strong>{item.source}</strong><time dateTime={item.time}>{shortTime.format(new Date(item.time))}</time></span>
                  <span className="status-pill danger-pill">Phishing</span>
                </li>;
              })}
            </ul>
          ) : <div className="recent-empty">
            <span className="icon-tile"><ActivityIcon size={19} /></span>
            <div>
              <strong>{historyError ? "Activity unavailable" : historyLoading ? "Loading activity…" : "No flagged scans"}</strong>
              <p>{historyError ? "Open Activity to refresh your history." : "New phishing predictions will appear here."}</p>
            </div>
          </div>}
        </section>
        <MonitoringCard messages={messages} onSettings={() => navigate("settings")} />
      </div>
    </div>
  );
}

function Metric({ icon: Icon, label, value, note, danger }) {
  return (
    <article className="card metric">
      <span className={danger ? "icon-tile icon-danger" : "icon-tile"}><Icon size={19} /></span>
      <div className="metric-label"><span>{label}</span><small>{note}</small></div>
      <strong>{value == null ? "—" : value.toLocaleString()}</strong>
    </article>
  );
}

function App() {
  const [theme, setTheme] = useState(savedTheme);
  const [route, setRoute] = useState({ page: "overview", option: "", revision: 0 });
  const [backend, setBackend] = useState({ state: native ? "checking" : "offline", detail: native ? "Checking FastAPI…" : "Open the native app to connect." });
  const [apiHistory, setApiHistory] = useState(null);
  const [apiError, setApiError] = useState("");
  const [historyLoading, setHistoryLoading] = useState(native);
  const historyRequest = useRef(false);
  const messages = useMessages(native);
  const content = useRef(null);

  const checkBackend = useCallback(async () => {
    if (!native) return;
    setBackend({ state: "checking", detail: "Checking FastAPI…" });
    try {
      await invoke("backend_health");
      setBackend({ state: "connected", detail: "Local FastAPI is connected." });
    } catch (error) {
      setBackend({ state: "offline", detail: String(error) });
    }
  }, []);

  const refreshHistory = useCallback(async () => {
    if (!native || historyRequest.current) return;
    historyRequest.current = true;
    setHistoryLoading(true);
    try {
      setApiHistory(await invoke("backend_history"));
      setApiError("");
    } catch (error) {
      setApiError(String(error));
    } finally {
      historyRequest.current = false;
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => { void checkBackend(); void refreshHistory(); }, [checkBackend, refreshHistory]);
  useEffect(() => { rememberTheme(theme); }, [theme]);

  const navigate = useCallback((page, option = "") => {
    setRoute(old => ({ page, option, revision: old.revision + 1 }));
    if (page === "activity" || page === "overview") void refreshHistory();
  }, [refreshHistory]);

  useEffect(() => {
    if (!route.revision || !content.current) return;
    content.current.scrollTop = 0;
    content.current.querySelector("h1")?.focus({ preventScroll: true });
  }, [route]);

  useEffect(() => {
    function shortcuts(event) {
      if (!event.metaKey || event.altKey || event.ctrlKey || event.shiftKey) return;
      const page = event.key === "," ? pages[3] : pages[Number(event.key) - 1];
      if (!page) return;
      event.preventDefault();
      navigate(page.id);
    }
    window.addEventListener("keydown", shortcuts);
    return () => window.removeEventListener("keydown", shortcuts);
  }, [navigate]);

  const page = pages.find(item => item.id === route.page);
  const records = combineHistory(apiHistory?.items ?? [], messages.history ?? []);
  const totals = apiHistory && messages.summary && !apiError && !messages.historyError ? {
    scans: apiHistory.total_scans + messages.summary.total_scans,
    flagged: apiHistory.phishing_detections + messages.summary.phishing_detections,
  } : null;
  const historyError = apiError || messages.historyError;
  const connectionName = backend.state === "connected" ? "Connected" : backend.state === "checking" ? "Checking…" : "Offline";
  return (
    <div className="app" data-theme={theme}>
      <aside className="sidebar" aria-label="SentinelAI">
        <div className="wordmark">
          <img className="wordmark-full" src={theme === "ember" ? emberLogo : navyLogo} alt="SentinelAI" />
          <img className="wordmark-small" src={theme === "ember" ? emberIcon : navyIcon} alt="SentinelAI" />
        </div>
        <nav className="navigation" aria-label="Main navigation">
          {pages.map(({ id, title, icon: Icon }, index) => (
            <button type="button" key={id} aria-current={id === page.id ? "page" : undefined}
              aria-label={title} aria-keyshortcuts={`Meta+${index + 1}`} title={`${title} (⌘${index + 1})`}
              onClick={() => navigate(id)}>
              <Icon size={18} aria-hidden="true" /><span>{title}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-status" title={`Local API · ${connectionName}`}>
          <span className={`connection-dot ${backend.state}`} />
          <div><strong>Local API</strong><small>{connectionName}</small></div>
        </div>
      </aside>

      <main className="workspace" ref={content}>
        <div className="page" key={route.revision}>
          <header className="page-heading">
            <div><h1 tabIndex={-1}>{page.title}</h1><p>{page.description}</p></div>
            {page.id === "overview" && <span className="workspace-label"><span className="workspace-label-icon"><ShieldCheck size={15} /></span> On-device analysis</span>}
          </header>
          {page.id === "overview" && <Overview backend={backend} messages={messages} totals={totals} theme={theme} navigate={navigate}
            records={records} historyLoading={historyLoading} historyError={historyError} />}
          {page.id === "activity" && <Activity records={records} loading={historyLoading} error={historyError}
            onRefresh={refreshHistory} messages={messages} initialFilter={route.option || "all"} />}
          {page.id === "scan" && <Scan native={native} initialKind={route.option || "url"} onScan={refreshHistory} />}
          {page.id === "settings" && <Settings messages={messages} theme={theme} setTheme={setTheme}
            backend={backend} checkBackend={() => { void checkBackend(); void refreshHistory(); }} />}
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
