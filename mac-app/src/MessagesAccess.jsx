import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Check, ChevronRight, CircleHelp, Clock3, Database, KeyRound, MessageSquare,
  Palette, Pause, Play, RefreshCw, Server, ShieldCheck, Square, Trash2,
} from "lucide-react";
import "./settings.css";

const accessLabels = {
  ready: "Verified",
  denied: "Denied",
  busy: "Busy",
  unavailable: "Unavailable",
  unsupported: "Unsupported",
};

const statusLabels = {
  stopped: "Off",
  running: "Monitoring",
  paused: "Paused",
};

const normalMessages = new Set([
  "Monitoring new incoming plaintext messages.",
  "Monitoring is paused. Resume to check messages that arrived while paused.",
  "Monitoring is off.",
]);

const shortTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function formatTime(value) {
  const date = new Date(value);
  return value && Number.isFinite(date.getTime()) ? shortTime.format(date) : "No scans yet";
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

export function useMessages(native) {
  const [consent, setConsent] = useState(false);
  const [access, setAccess] = useState(null);
  const [monitor, setMonitor] = useState(null);
  const [statusError, setStatusError] = useState("");
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(native);
  const [historyError, setHistoryError] = useState("");
  const [summary, setSummary] = useState(null);
  const [summaryError, setSummaryError] = useState("");
  const [historyNotice, setHistoryNotice] = useState("");
  const [notice, setNotice] = useState("");
  const [operation, setOperation] = useState("");
  const working = useRef(false);
  const generation = useRef(0);

  useEffect(() => {
    if (!native) return;
    let cancelled = false;
    let timer;

    async function refresh() {
      if (cancelled) return;
      const revision = generation.current;
      if (!working.current) {
        const [status, entries, counts] = await Promise.allSettled([
          invoke("monitoring_status"),
          invoke("message_scan_history"),
          invoke("message_history_summary"),
        ]);
        if (!cancelled && generation.current === revision) {
          if (status.status === "fulfilled") {
            setMonitor(status.value);
            setStatusError("");
          } else {
            setStatusError(errorMessage(status.reason));
          }
          if (entries.status === "fulfilled") {
            setHistory(entries.value);
            setHistoryError("");
          } else {
            setHistoryError(errorMessage(entries.reason));
          }
          if (counts.status === "fulfilled") {
            setSummary(counts.value);
            setSummaryError("");
          } else {
            setSummaryError(errorMessage(counts.reason));
          }
          setHistoryLoading(false);
        }
      }
      if (!cancelled) timer = window.setTimeout(refresh, 2200);
    }

    void refresh();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [native]);

  async function perform(kind, action) {
    if (!native || working.current) return false;
    working.current = true;
    generation.current += 1;
    setOperation(kind);
    const setFeedback = kind === "delete" ? setHistoryNotice : setNotice;
    setFeedback("");
    try {
      await action();
      return true;
    } catch (error) {
      setFeedback(errorMessage(error));
      return false;
    } finally {
      working.current = false;
      setOperation("");
    }
  }

  function openSettings() {
    if (!consent) return false;
    return perform("settings", async () => {
      setAccess(null);
      await invoke("open_privacy_settings");
      setNotice("After allowing access in macOS, return here and verify again.");
    });
  }

  function checkAccess() {
    if (!consent) return false;
    return perform("verify", async () => {
      setAccess(null);
      setAccess(await invoke("check_messages_access"));
    });
  }

  function updateMonitoring(command) {
    if (command === "start_monitoring" && (!consent || access?.status !== "ready")) return false;
    if (command === "resume_monitoring" && !consent) return false;
    return perform(command, async () => {
      setMonitor(await invoke(command));
      setStatusError("");
    });
  }

  async function changeConsent(checked) {
    if (!checked) {
      // Stop even if the most recent status request failed.
      if (!await updateMonitoring("stop_monitoring")) return;
    }
    setConsent(checked);
    setAccess(null);
    setNotice("");
  }

  function deleteHistory() {
    return perform("delete", async () => {
      const result = await invoke("clear_message_scan_history");
      setHistory([]);
      setHistoryError("");
      setSummary({ total_scans: 0, phishing_detections: 0 });
      setSummaryError("");
      setHistoryNotice(`Deleted ${result.deleted} Messages scan ${result.deleted === 1 ? "result" : "results"}.`);
    });
  }

  return {
    native, consent, access, monitor, statusError, history, historyLoading, historyError, summary,
    summaryError, historyNotice, notice, operation, changeConsent, openSettings, checkAccess,
    updateMonitoring, deleteHistory,
  };
}

function Tile({ icon: Icon }) {
  return <span className="settings-icon" aria-hidden="true"><Icon size={18} strokeWidth={1.8} /></span>;
}

function Status({ tone = "neutral", children }) {
  return <span className={`settings-status ${tone}`} role="status"><span aria-hidden="true" />{children}</span>;
}

function MonitoringStatus({ messages }) {
  const unavailable = !messages.native || messages.statusError;
  const state = unavailable ? null : messages.monitor?.state;
  const label = statusLabels[state] ?? (unavailable ? "Unavailable" : "Checking");
  return <Status tone={state === "running" ? "positive" : state === "paused" ? "caution" : "neutral"}>{label}</Status>;
}

function MonitoringActions({ messages, onSettings }) {
  const { monitor, consent, access, updateMonitoring, native, operation, statusError } = messages;
  const disabled = !native || Boolean(operation);
  const canStart = consent && access?.status === "ready" && !statusError;
  const state = monitor?.state;
  if (!state || state === "stopped") {
    if (onSettings && !canStart) {
      return <button type="button" className="button quiet" onClick={onSettings}>Set up Messages <ChevronRight size={14} aria-hidden="true" /></button>;
    }
    return (
      <button className="button primary" type="button" disabled={disabled || !canStart || !state}
        onClick={() => void updateMonitoring("start_monitoring")}>
        <Play size={15} aria-hidden="true" />{operation === "start_monitoring" ? "Starting…" : "Start monitoring"}
      </button>
    );
  }

  const paused = state === "paused";
  return (
    <>
      <button className="button" type="button" disabled={disabled || (paused && !consent)}
        onClick={() => void updateMonitoring(paused ? "resume_monitoring" : "pause_monitoring")}>
        {paused ? <Play size={15} aria-hidden="true" /> : <Pause size={15} aria-hidden="true" />}
        {paused ? "Resume" : "Pause"}
      </button>
      <button className="button quiet" type="button" disabled={disabled}
        onClick={() => void updateMonitoring("stop_monitoring")}>
        <Square size={13} aria-hidden="true" />{operation === "stop_monitoring" ? "Stopping…" : "Stop"}
      </button>
    </>
  );
}

function MonitoringFeedback({ messages }) {
  const detail = messages.monitor?.detail;
  const warning = detail && !normalMessages.has(detail) ? detail : "";
  const pauseNote = messages.monitor?.state === "paused" ? "Resume to check messages received during the pause." : "";
  const text = messages.notice || messages.statusError || warning || pauseNote;
  if (!text) return null;
  return <p className="settings-feedback" role="status">{text}</p>;
}

export function MonitoringCard({ messages, onSettings }) {
  const permission = accessLabels[messages.access?.status] ?? "Not checked";
  const lastScan = messages.historyError ? "Unavailable" : messages.historyLoading
    ? "Checking…" : formatTime(messages.history[0]?.detected_at);
  return (
    <section className="card monitoring-card" aria-labelledby="overview-messages">
      <div className="settings-heading">
        <Tile icon={MessageSquare} />
        <h2 id="overview-messages">Messages monitoring</h2>
        <MonitoringStatus messages={messages} />
      </div>
      <dl className="monitoring-facts">
        <div>
          <dt><KeyRound size={14} aria-hidden="true" />Read access</dt>
          <dd>{permission}</dd>
        </div>
        <div>
          <dt><Clock3 size={14} aria-hidden="true" />Last scan</dt>
          <dd>{lastScan}</dd>
        </div>
      </dl>
      <div className="settings-actions">
        <MonitoringActions messages={messages} onSettings={onSettings} />
      </div>
      <MonitoringFeedback messages={messages} />
    </section>
  );
}

const availableThemes = [
  { key: "navy", name: "Midnight Navy", colour: "#03094B" },
  { key: "ember", name: "Warm Ember", colour: "#541504" },
];

function Appearance({ theme, setTheme }) {
  return (
    <section className="card settings-panel" aria-labelledby="appearance-heading">
      <div className="settings-heading">
        <Tile icon={Palette} />
        <h2 id="appearance-heading">Appearance</h2>
      </div>
      <div className="theme-choices" role="group" aria-label="Colour scheme">
        {availableThemes.map(({ key, name, colour }) => (
          <button key={key} className="theme-option" data-swatch={key} type="button"
            aria-pressed={theme === key} onClick={() => setTheme(key)}>
            <span className="theme-preview" aria-hidden="true"><span /><span /></span>
            <span className="theme-option-label"><strong>{name}</strong><small>{colour}</small></span>
            {theme === key && <Check size={15} aria-hidden="true" className="theme-check" />}
          </button>
        ))}
      </div>
    </section>
  );
}

function MessagePreferences({ messages }) {
  const disabled = !messages.native || Boolean(messages.operation);
  const access = messages.access?.status;
  return (
    <section className="card settings-panel" aria-labelledby="messages-settings-heading">
      <div className="settings-heading">
        <Tile icon={MessageSquare} />
        <h2 id="messages-settings-heading">Messages monitoring</h2>
        <MonitoringStatus messages={messages} />
      </div>
      <label className="settings-row settings-toggle">
        <span><strong>Allow local monitoring</strong><small>Read new incoming plaintext when you start monitoring.</small></span>
        <input type="checkbox" role="switch" checked={messages.consent} disabled={disabled}
          onChange={event => void messages.changeConsent(event.target.checked)} />
        <span className="switch-track" aria-hidden="true" />
      </label>
      <div className="settings-row settings-access">
        <span>
          <strong>Full Disk Access</strong>
          <small>{messages.access?.message ?? "Open macOS settings, then verify Messages read access."}</small>
        </span>
        <Status tone={access === "ready" ? "positive" : access ? "caution" : "neutral"}>
          {accessLabels[access] ?? "Not checked"}
        </Status>
      </div>
      <div className="settings-actions">
        <button type="button" className="button" onClick={() => void messages.openSettings()} disabled={disabled || !messages.consent}>
          <KeyRound size={14} aria-hidden="true" />{messages.operation === "settings" ? "Opening…" : "Open Privacy Settings"}
        </button>
        <button type="button" className="button" onClick={() => void messages.checkAccess()} disabled={disabled || !messages.consent}>
          <ShieldCheck size={15} aria-hidden="true" />{messages.operation === "verify" ? "Verifying…" : "Verify access"}
        </button>
        <MonitoringActions messages={messages} />
      </div>
      <p className="settings-model-note"><CircleHelp size={14} aria-hidden="true" />
        The email-trained model has not been validated for SMS or iMessage.
      </p>
      <MonitoringFeedback messages={messages} />
    </section>
  );
}

function Backend({ backend, checkBackend, native }) {
  const connected = backend?.state === "connected";
  const checking = backend?.state === "checking";
  return (
    <section className="card settings-panel settings-utility" aria-labelledby="backend-settings-heading">
      <div className="settings-heading">
        <Tile icon={Server} />
        <h2 id="backend-settings-heading">Local service</h2>
        <Status tone={connected ? "positive" : checking ? "neutral" : "caution"}>
          {connected ? "Connected" : checking ? "Checking" : "Offline"}
        </Status>
      </div>
      <p>{connected ? "FastAPI is ready for local scans." : backend?.detail ?? "Check if FastAPI is available."}</p>
      <button className="button quiet" type="button" disabled={!native || checking} onClick={checkBackend}>
        <RefreshCw size={14} aria-hidden="true" />Check connection
      </button>
    </section>
  );
}

function PrivacyHistory({ messages }) {
  const [confirm, setConfirm] = useState(false);
  const deleteButton = useRef(null);
  const cancelButton = useRef(null);
  const hasHistory = (messages.summary?.total_scans ?? messages.history.length) > 0;

  useEffect(() => {
    if (confirm) cancelButton.current?.focus();
  }, [confirm]);

  function cancelDeletion() {
    setConfirm(false);
    window.requestAnimationFrame(() => deleteButton.current?.focus());
  }

  return (
    <section className="card settings-panel settings-utility" aria-labelledby="privacy-settings-heading">
      <div className="settings-heading">
        <Tile icon={Database} />
        <h2 id="privacy-settings-heading">Privacy &amp; history</h2>
      </div>
      <p>Messages history stores the score, result and scan time.</p>
      {confirm ? (
        <div className="settings-confirm" role="group" aria-label="Confirm Messages history deletion">
          <p>Remove saved Messages scan results?</p>
          <div className="settings-actions">
            <button type="button" className="button danger" disabled={Boolean(messages.operation)} onClick={async () => {
              if (await messages.deleteHistory()) setConfirm(false);
            }}>{messages.operation === "delete" ? "Deleting…" : "Delete history"}</button>
            <button ref={cancelButton} type="button" className="button quiet" onClick={cancelDeletion} disabled={Boolean(messages.operation)}>Cancel</button>
          </div>
        </div>
      ) : (
        <button ref={deleteButton} className="button quiet settings-delete" type="button"
          disabled={!messages.native || !hasHistory || Boolean(messages.operation)} onClick={() => setConfirm(true)}>
          <Trash2 size={14} aria-hidden="true" />Delete Messages history
        </button>
      )}
      {(messages.historyNotice || messages.historyError) && (
        <p className="settings-feedback" role="status">{messages.historyNotice || messages.historyError}</p>
      )}
    </section>
  );
}

export default function Settings({ messages, theme, setTheme, backend, checkBackend }) {
  return (
    <div className="settings-grid">
      <Appearance theme={theme} setTheme={setTheme} />
      <MessagePreferences messages={messages} />
      <div className="settings-utilities">
        <Backend backend={backend} checkBackend={checkBackend} native={messages.native} />
        <PrivacyHistory messages={messages} />
      </div>
    </div>
  );
}
