import { useEffect, useState } from "react";
import {
  Activity, CircleHelp, Fingerprint, History as HistoryIcon, LayoutGrid,
  Link2, ListChecks, Mail, ScanLine, ShieldAlert,
} from "lucide-react";
import { getHealth, getHistory } from "./api";
import type { HistoryResponse, ScanRecord } from "./api";
import History from "./History";
import Scanner from "./Scanners";
import ScannerArt from "./ScannerArt";

const tools = [
  { id: "url", label: "URL Scanner", icon: Link2, description: "Check a link for phishing signals before you visit it." },
  { id: "email", label: "Email Scanner", icon: Mail, description: "Check whether a message resembles known phishing emails." },
  { id: "privacy", label: "Privacy Scanner", icon: Fingerprint, description: "Find and redact personal details in text before you share it." },
] as const;
const pages = [
  { id: "dashboard", label: "Dashboard", icon: LayoutGrid },
  ...tools,
  { id: "history", label: "Scan History", icon: HistoryIcon },
] as const;

type Page = (typeof pages)[number]["id"];

function currentPage(): Page {
  const route = window.location.hash.slice(1);
  return pages.find(page => page.id === route)?.id ?? "dashboard";
}

function App() {
  const [page, setPage] = useState(currentPage);
  const [apiStatus, setApiStatus] = useState("Checking API");
  const pageLabel = pages.find(item => item.id === page)?.label;

  useEffect(() => {
    const onNavigate = () => setPage(currentPage());
    window.addEventListener("hashchange", onNavigate);
    return () => window.removeEventListener("hashchange", onNavigate);
  }, []);

  useEffect(() => {
    document.title = pageLabel + " · SentinelAI";
    window.scrollTo(0, 0);
  }, [pageLabel]);

  useEffect(() => {
    const controller = new AbortController();
    async function check() {
      try {
        const health = await getHealth(controller.signal);
        if (!controller.signal.aborted) setApiStatus(health.status === "ok" ? "API online" : "API unavailable");
      } catch {
        if (!controller.signal.aborted) setApiStatus("API unavailable");
      }
    }
    void check();
    const interval = window.setInterval(check, 15_000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, []);

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link" onClick={event => {
        event.preventDefault();
        document.getElementById("main-content")?.focus();
      }}>Skip to content</a>
      <aside className="sidebar">
        <a className="brand" href="#dashboard" aria-label="SentinelAI dashboard">
          <img src="/sentinel.svg" width="35" height="40" alt="" />
          <span>Sentinel<span className="brand-accent">AI</span><small>Phishing &amp; privacy</small></span>
        </a>
        <nav className="nav-list" aria-label="Main navigation">
          {pages.map(({ id, label, icon: Icon }) => (
            <a href={"#" + id} key={id} className={id === page ? "nav-active" : ""} aria-current={id === page ? "page" : undefined}>
              <Icon size={18} aria-hidden="true" />
              <span className="nav-label">{label}</span>
              <span className="nav-short">{id === "dashboard" ? "Home" : id === "history" ? "History" : id === "url" ? "URL" : id === "email" ? "Email" : "Privacy"}</span>
            </a>
          ))}
        </nav>
        <div className="sidebar-foot"><CircleHelp size={17} aria-hidden="true" /><p>Scans run locally. History stores scan metadata only.</p></div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <span className="topbar-label">Workspace <span aria-hidden="true">/</span> <strong>{pageLabel}</strong></span>
          <span role="status" className={"connection " + (apiStatus === "API online" ? "connected" : apiStatus === "API unavailable" ? "disconnected" : "")}>
            <i aria-hidden="true" />{apiStatus}
          </span>
        </header>
        <main id="main-content" tabIndex={-1} className="page-content">
          {page === "dashboard" ? <Dashboard /> : page === "history" ? <History /> : <Scanner key={page} type={page} onScan={() => setApiStatus("API online")} />}
        </main>
      </div>
    </div>
  );
}

function Dashboard() {
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    getHistory({ limit: 5, signal: controller.signal })
      .then(setHistory)
      .catch(err => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Could not load scan history.");
      });
    return () => controller.abort();
  }, [attempt]);

  const metrics = [
    { label: "Total scans", value: history?.total_scans, icon: ScanLine, color: "url" },
    { label: "Phishing detections", value: history?.phishing_detections, icon: ShieldAlert, color: "email" },
    { label: "Private details found", value: history?.privacy_matches, icon: Fingerprint, color: "privacy" },
  ];

  return (
    <>
      <header className="dashboard-heading">
        <div>
          <h1>Dashboard</h1>
          <p>Check suspicious links and emails, or redact private details before sharing text.</p>
        </div>
        <a href="#history" className="quiet-button"><HistoryIcon size={17} aria-hidden="true" /> Scan history</a>
      </header>

      <section aria-label="Scan totals" className="metrics grid grid-cols-1 sm:grid-cols-3">
        {metrics.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className={"metric accent-" + color}>
            <span className="metric-icon"><Icon size={19} strokeWidth={1.7} aria-hidden="true" /></span>
            <div><strong>{value?.toLocaleString() ?? "—"}</strong><span>{label}</span></div>
          </div>
        ))}
      </section>

      <section className="scanner-section" aria-labelledby="scanner-heading">
        <h2 id="scanner-heading">Choose a scanner</h2>
        <div className="scanner-grid grid grid-cols-1 md:grid-cols-3">
          {tools.map(({ id, label, description, icon: Icon }) => (
            <a className={"scanner-card accent-" + id} key={id} href={"#" + id}>
              <ScannerArt type={id} />
              <div className="scanner-card-copy">
                <h3><Icon size={18} aria-hidden="true" /> {label}</h3>
                <p>{description}</p>
              </div>
              <div className="scanner-card-action">Open scanner</div>
            </a>
          ))}
        </div>
      </section>

      <div className={history?.daily_activity.length ? "dashboard-bottom has-activity" : "dashboard-bottom"}>
        <section className="recent" aria-labelledby="recent-heading">
          <div className="recent-header">
            <h2 id="recent-heading"><ListChecks size={19} aria-hidden="true" /> Recent scans</h2>
            <a href="#history">View all</a>
          </div>
          {history && history.items.length > 0 ? <RecentScans items={history.items} /> : (
            <div className="recent-empty">
              <span className="recent-icon"><Activity size={21} aria-hidden="true" /></span>
              <div>
                <strong>{error ? "History unavailable" : history ? "No scans yet" : "Loading scans…"}</strong>
                <p>{error || (history ? "Results from your first scan will appear here." : "Reading the local scan history.")}</p>
              </div>
              {error && <button className="quiet-button" onClick={() => { setError(""); setAttempt(value => value + 1); }}>Try again</button>}
            </div>
          )}
        </section>
        {history && history.daily_activity.length > 0 && <ActivityChart activity={history.daily_activity} />}
      </div>
    </>
  );
}

function RecentScans({ items }: { items: ScanRecord[] }) {
  const timeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  return (
    <ul className="recent-list">
      {items.map(item => {
        const scanner = tools.find(tool => tool.id === item.scan_type);
        const Icon = scanner?.icon ?? ScanLine;
        return (
          <li key={item.id}>
            <span className={"recent-type accent-" + item.scan_type}><Icon size={17} aria-hidden="true" /> {scanner?.label}</span>
            <span className={"recent-verdict risk-" + item.risk_level.toLowerCase()}>{item.prediction}</span>
            <time dateTime={item.timestamp}>{timeFormat.format(new Date(item.timestamp))}</time>
          </li>
        );
      })}
    </ul>
  );
}

function ActivityChart({ activity }: { activity: HistoryResponse["daily_activity"] }) {
  const counts = new Map(activity.map(({ date, count }) => [date, count]));
  const max = Math.max(...counts.values(), 1);
  const today = new Date();
  const label = new Intl.DateTimeFormat(undefined, { weekday: "short", timeZone: "UTC" });
  const fullDate = new Intl.DateTimeFormat(undefined, { dateStyle: "long", timeZone: "UTC" });
  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(today);
    date.setUTCDate(today.getUTCDate() - 6 + index);
    return { date, count: counts.get(date.toISOString().slice(0, 10)) ?? 0 };
  });

  return (
    <section className="activity" aria-labelledby="activity-heading">
      <div className="recent-header">
        <h2 id="activity-heading"><Activity size={19} aria-hidden="true" /> Scan activity</h2>
        <span>7 days · UTC</span>
      </div>
      <ul className="activity-bars">
        {days.map(({ date, count }) => (
          <li key={date.toISOString()}>
            <span className="sr-only">{fullDate.format(date)}: {count} scans</span>
            <span className="activity-column" aria-hidden="true">
              <span className="activity-count">{count}</span>
              <span className="activity-bar" style={{ height: count ? (count / max * 100) + "%" : "2px" }} />
            </span>
            <span aria-hidden="true">{label.format(date)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default App;
