import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight, Fingerprint, History as HistoryIcon, Link2, ListFilter, LoaderCircle, Mail, RefreshCw } from 'lucide-react'
import { getHistory } from './api'
import type { HistoryResponse, ScanType } from './api'
import './panels.css'

const scanners = {
  url: { label: 'URL', icon: Link2 },
  email: { label: 'Email', icon: Mail },
  privacy: { label: 'Privacy', icon: Fingerprint },
} as const
const pageSize = 10

export default function History() {
  const [type, setType] = useState<ScanType | 'all'>('all')
  const [page, setPage] = useState(0)
  const [revision, setRevision] = useState(0)
  const [data, setData] = useState<HistoryResponse | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    setError('')
    setData(null)
    getHistory({ scanType: type === 'all' ? undefined : type, offset: page * pageSize, limit: pageSize, signal: controller.signal })
      .then(next => { if (!controller.signal.aborted) setData(next) })
      .catch(err => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : 'History could not be loaded.')
      })
    return () => controller.abort()
  }, [type, page, revision])

  return (
    <section className="sp-page sp-history">
      <header className="sp-page-heading"><h1>Scan History</h1><p>Review saved results from the URL, email and privacy scanners.</p></header>
      <div className="sp-surface">
        <div className="sp-history-toolbar">
          <div className="sp-filter-group" role="group" aria-label="Filter by scan type">
            <ListFilter size={17} aria-hidden="true" />
            {(['all', 'url', 'email', 'privacy'] as const).map(key => (
              <button type="button" key={key} aria-pressed={type === key} onClick={() => { setType(key); setPage(0) }}>
                {key === 'all' ? 'All scans' : scanners[key].label}
              </button>
            ))}
          </div>
          <button type="button" className="sp-text-btn" onClick={() => setRevision(n => n + 1)} aria-label="Refresh history"><RefreshCw size={15} /><span>Refresh</span></button>
        </div>
        {error
          ? <div className="sp-history-empty" role="alert"><p>{error}</p><button type="button" className="sp-secondary" onClick={() => setRevision(n => n + 1)}>Try again</button></div>
          : data === null
            ? <div className="sp-history-empty" role="status"><LoaderCircle size={24} className="sp-spin" /><p>Loading scan history…</p></div>
            : data.items.length === 0
              ? <div className="sp-history-empty"><span className="sp-reticle"><HistoryIcon size={30} strokeWidth={1.4} /></span>
                  <h2>{type === 'all' ? 'No scans yet' : 'No ' + scanners[type].label + ' scans yet'}</h2><p>Completed scans will appear here.</p></div>
              : <table className="sp-history-table">
                  <thead><tr><th scope="col">Scanner</th><th scope="col">Prediction</th><th scope="col">Risk level</th><th scope="col">Findings</th><th scope="col">Date &amp; time</th></tr></thead>
                  <tbody>
                    {data.items.map(row => {
                      const { label, icon: Icon } = scanners[row.scan_type]
                      const date = new Date(row.timestamp)
                      return <tr key={row.id}>
                        <th scope="row"><span className={'sp-type sp-' + row.scan_type}><Icon size={16} />{label}</span></th>
                        <td data-label="Prediction">{row.prediction}</td>
                        <td data-label="Risk level"><span className={'sp-history-risk sp-risk-' + row.risk_level.toLowerCase()}>{row.risk_level}</span></td>
                        <td data-label="Findings" className="sp-findings">{row.findings}</td>
                        <td data-label="Scanned"><time dateTime={row.timestamp}>{date.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })} <span>{date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</span></time></td>
                      </tr>
                    })}
                  </tbody>
                </table>}
        {data && data.total > 0 && <footer className="sp-pagination">
          <span>{page * pageSize + 1}–{page * pageSize + data.items.length} of {data.total} scans</span>
          <div>
            <button className="sp-secondary" type="button" disabled={page === 0} aria-label="Previous page" onClick={() => setPage(n => n - 1)}><ChevronLeft size={16} /></button>
            <button className="sp-secondary" type="button" disabled={(page + 1) * pageSize >= data.total} aria-label="Next page" onClick={() => setPage(n => n + 1)}><ChevronRight size={16} /></button>
          </div>
        </footer>}
      </div>
    </section>
  )
}
