import { useMemo, useState } from "react";
import {
  ArrowDown, ArrowUp, ArrowUpDown, ChevronDown, Globe2, ListFilter,
  Mail, MessageCircle, RefreshCw, ScanLine, ShieldCheck, Trash2,
} from "lucide-react";
import "./panels.css";

const sources = {
  url: { name: "URL scans", icon: Globe2 },
  email: { name: "Email scans", icon: Mail },
  messages: { name: "Apple Messages", icon: MessageCircle },
  privacy: { name: "Privacy scans", icon: ShieldCheck },
};

const date = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" });
const time = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const percent = new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 });

export function RiskBadge({ risk }) {
  if (!["High", "Medium", "Low"].includes(risk)) return <span className="activity-indeterminate">—</span>;
  return <span className={"activity-risk " + risk.toLowerCase()}>{risk} risk</span>;
}

function SortColumn({ label, field, sort, onSort }) {
  const direction = field === sort.field ? sort.direction : null;
  const Icon = direction === "descending" ? ArrowDown : direction === "ascending" ? ArrowUp : ArrowUpDown;
  return (
    <th scope="col" aria-sort={direction || undefined}>
      <button className="activity-sort" type="button" onClick={() => onSort(field)}>
        {label}<Icon size={12} aria-hidden="true" />
      </button>
    </th>
  );
}

function ActivityRow({ record }) {
  const Icon = sources[record.kind]?.icon || ScanLine;
  const timestamp = new Date(record.time);
  const validDate = !Number.isNaN(timestamp.valueOf());

  return (
    <tr>
      <td>
        <span className="activity-source">
          <span className="activity-source-icon"><Icon size={16} aria-hidden="true" /></span>
          {record.source}
        </span>
      </td>
      <td>
        {validDate ? (
          <time className="activity-time" dateTime={timestamp.toISOString()}>
            <span>{date.format(timestamp)}</span>
            <span>{time.format(timestamp)}</span>
          </time>
        ) : "—"}
      </td>
      <td>{record.prediction || "—"}</td>
      <td className="activity-probability">{record.probability == null ? "—" : percent.format(record.probability)}</td>
      <td><RiskBadge risk={record.risk} /></td>
    </tr>
  );
}

export default function Activity({ records, loading, error, onRefresh, messages, initialFilter = "all" }) {
  const [filter, setFilter] = useState(initialFilter === "flagged" ? "flagged" : "all");
  const [source, setSource] = useState("all");
  const [sort, setSort] = useState({ field: "time", direction: "descending" });
  const [confirmDelete, setConfirmDelete] = useState(false);
  const visible = useMemo(() => records
    .filter((record) => (source === "all" || record.kind === source)
      && (filter === "all" || record.prediction === "Phishing"))
    .sort((first, second) => {
      const descending = sort.direction === "descending";
      if (sort.field === "probability") {
        if (first.probability == null) return second.probability == null ? 0 : 1;
        if (second.probability == null) return -1;
        return descending ? second.probability - first.probability : first.probability - second.probability;
      }
      const firstDate = Date.parse(first.time) || 0;
      const secondDate = Date.parse(second.time) || 0;
      return descending ? secondDate - firstDate : firstDate - secondDate;
    }), [filter, records, source, sort]);

  function sortBy(field) {
    setSort((previous) => ({
      field,
      direction: previous.field === field && previous.direction === "descending" ? "ascending" : "descending",
    }));
  }

  const blocked = Boolean(messages.operation);
  const canDelete = messages.history.length > 0;
  const activityError = error || messages.historyError;

  return (
    <section className="card activity-panel" aria-label="Scan activity">
      <header className="activity-toolbar">
        <div className="segmented" role="group" aria-label="Activity filter">
          <button type="button" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>All activity</button>
          <button type="button" aria-pressed={filter === "flagged"} onClick={() => setFilter("flagged")}>Flagged</button>
        </div>
        <div className="activity-toolbar-actions">
          <label className="activity-select">
            <ListFilter size={15} aria-hidden="true" />
            <select aria-label="Filter by source" value={source} onChange={(event) => setSource(event.target.value)}>
              <option value="all">All sources</option>
              {Object.entries(sources).map(([kind, { name }]) => <option key={kind} value={kind}>{name}</option>)}
            </select>
            <ChevronDown size={13} aria-hidden="true" />
          </label>
          <button className="button quiet activity-refresh" type="button" disabled={loading} onClick={onRefresh} aria-label="Refresh activity" title="Refresh activity">
            <RefreshCw size={15} className={loading ? "scan-spinner" : ""} aria-hidden="true" />
          </button>
        </div>
      </header>

      {visible.length > 0 && activityError && (
        <p className="activity-error" role="status">{activityError}</p>
      )}
      {visible.length > 0 ? (
        <div className="activity-table-wrap">
          <table className="activity-table">
            <thead>
              <tr>
                <th scope="col">Source</th>
                <SortColumn label="Scanned" field="time" sort={sort} onSort={sortBy} />
                <th scope="col">Prediction</th>
                <SortColumn label="Phishing probability" field="probability" sort={sort} onSort={sortBy} />
                <th scope="col">Risk</th>
              </tr>
            </thead>
            <tbody>{visible.map((record) => <ActivityRow key={record.key} record={record} />)}</tbody>
          </table>
        </div>
      ) : (
        <div className="activity-empty" role={activityError ? "status" : undefined}>
          <span className="scan-placeholder"><ScanLine size={24} aria-hidden="true" /></span>
          <h2>{loading ? "Loading activity" : activityError ? "Activity unavailable" : filter === "flagged" ? "No flagged scans" : "No scans to show"}</h2>
          <p>{loading ? "Checking saved scan results."
            : activityError || (filter === "flagged" ? "Phishing predictions appear here when flagged."
            : source === "all" ? "Results will appear here after a scan." : "Try another source or run a scan.")}</p>
        </div>
      )}

      <footer className="activity-footer">
        <span role="status">{messages.historyNotice || (visible.length > 0 ? `${visible.length} recent ${visible.length === 1 ? "result" : "results"}` : "Recent scan history")}</span>
        {confirmDelete ? (
          <div className="activity-delete" role="group" aria-label="Confirm deletion">
            <p>Delete all Messages scan results? Other scan history will be kept.</p>
            <div>
              <button className="button quiet" type="button" disabled={blocked} onClick={() => setConfirmDelete(false)}>Cancel</button>
              <button className="button danger" type="button" disabled={blocked} onClick={async () => {
                if (await messages.deleteHistory()) setConfirmDelete(false);
              }}>{messages.operation === "delete" ? "Deleting…" : "Delete results"}</button>
            </div>
          </div>
        ) : canDelete && (
          <button className="button quiet activity-delete-button" type="button" disabled={blocked} onClick={() => setConfirmDelete(true)}>
            <Trash2 size={15} aria-hidden="true" /> Delete Messages history
          </button>
        )}
      </footer>
    </section>
  );
}
