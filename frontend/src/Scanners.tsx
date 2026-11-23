import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Check, Clipboard, Fingerprint, FlaskConical, Link2, LoaderCircle, LockKeyhole, Mail, ScanLine, ShieldAlert, ShieldCheck } from 'lucide-react'
import { runScan } from './api'
import type { ScanResult, ScanType } from './api'
import ScannerArt from './ScannerArt'
import './panels.css'

const scanners = {
  url: {
    name: 'URL Scanner',
    icon: Link2,
    intro: 'Check a link for signs of phishing without opening the page.',
    label: 'Website address',
    placeholder: 'https://example.com',
    sample: 'https://en.wikipedia.org/wiki/Internet',
    helper: 'Include http:// or https:// at the start of the address.',
    action: 'Scan URL',
    method: 'Gradient-boosted trees',
    how: 'The model checks the structure of the host and path. The characteristics below describe the full address.',
  },
  email: {
    name: 'Email Scanner',
    icon: Mail,
    intro: 'Check the wording of a message for patterns associated with phishing.',
    label: 'Email content',
    placeholder: 'Paste the subject and body of the email here…',
    sample: 'Subject: Science fair\n\nHi everyone,\nOur science fair starts at 10 tomorrow in the school hall. Please bring your project notes.',
    helper: 'Include the subject and body. You can leave out names and contact details.',
    action: 'Analyze email',
    method: 'TF-IDF + logistic regression',
    how: 'The classifier looks at the words and pairs of words in the message and compares them with patterns learned from labeled emails.',
  },
  privacy: {
    name: 'Privacy Scanner',
    icon: Fingerprint,
    intro: 'Find and hide personal information before you share a piece of text.',
    label: 'Text to redact',
    placeholder: 'Paste the text you want to check…',
    sample: 'For the science fair, email student@example.org or call +91 9876543210.',
    helper: 'Review the redacted copy before sharing it.',
    action: 'Redact text',
    method: 'Pattern matching',
    how: 'The detector checks for email addresses, Indian mobile numbers and 12-digit Aadhaar-like numbers.',
  },
} as const

const featureLabels: Record<string, string> = {
  URLLength: 'URL length',
  DomainLength: 'Domain length',
  IsDomainIP: 'IP address as host',
  NoOfSubDomain: 'Subdomain count',
  NoOfLettersInURL: 'Letters',
  NoOfDegitsInURL: 'Digits',
  NoOfQMarkInURL: 'Question marks',
  NoOfAmpersandInURL: 'Ampersands',
  IsHTTPS: 'Uses HTTPS',
}

function ModelResult({ result, type }: { result: ScanResult; type: ScanType }) {
  const phishing = result.prediction === 'Phishing'
  const insufficient = result.prediction === 'Insufficient information'
  const VerdictIcon = insufficient ? ScanLine : phishing ? ShieldAlert : ShieldCheck
  const percent = result.phishing_probability == null ? null : 100 * result.phishing_probability
  return (
    <div className="sp-result-body">
      <div className={'sp-verdict ' + (insufficient ? 'sp-private' : phishing ? 'sp-danger' : 'sp-clear')}>
        <VerdictIcon size={29} aria-hidden="true" />
        <div><span className="sp-meta">{insufficient ? 'Assessment' : 'Model prediction'}</span><h3>{result.prediction}</h3></div>
        {!insufficient && <span className="sp-risk">{result.risk_level} risk</span>}
      </div>
      <p className="sp-explanation">
        {insufficient ? result.reason ?? 'The model could not assess this input reliably.' : phishing
          ? 'This ' + (type === 'url' ? 'address' : 'message') + ' resembles phishing examples in the training data. Verify the sender before acting.'
          : 'The model classified this ' + (type === 'url' ? 'address' : 'message') + ' as legitimate. Check the source before sharing information.'}
      </p>
      {percent !== null && <div className="sp-probability">
        <div><span>Phishing probability</span><strong>{percent.toLocaleString(undefined, { maximumFractionDigits: 2 })}%</strong></div>
        <progress max={100} value={percent} aria-label="Model phishing probability" />
      </div>}
      {result.features && <details className="sp-details">
        <summary>URL characteristics <span>{Object.keys(result.features).length} features</span></summary>
        <dl className="sp-features">
          {Object.entries(result.features).map(([key, value]) => <div key={key}>
            <dt>{featureLabels[key] || key}</dt>
            <dd>{key === 'IsDomainIP' || key === 'IsHTTPS' ? (value ? 'Yes' : 'No') : value}</dd>
          </div>)}
        </dl>
      </details>}
    </div>
  )
}

function PrivacyResult({ result }: { result: ScanResult }) {
  const [copyStatus, setCopyStatus] = useState('')
  const labels = { emails: 'Email addresses', phone_numbers: 'Phone numbers', aadhaar_numbers: 'Aadhaar-like numbers' }
  async function copyText() {
    try {
      await navigator.clipboard.writeText(result.redacted_text ?? '')
      setCopyStatus('Copied')
    } catch {
      setCopyStatus('Select the redacted text below and copy it manually.')
    }
  }
  return (
    <div className="sp-result-body">
      <div className="sp-verdict sp-private">
        <Fingerprint size={29} aria-hidden="true" />
        <div><span className="sp-meta">Pattern check</span><h3>{result.prediction}</h3></div>
        <span className="sp-risk">{result.risk_level} risk</span>
      </div>
      <dl className="sp-features sp-counts">
        {(Object.keys(labels) as (keyof typeof labels)[]).map(key => <div key={key}><dt>{labels[key]}</dt><dd>{result.counts?.[key] ?? 0}</dd></div>)}
      </dl>
      <div className="sp-result-label"><h4>Redacted text</h4>
        <button type="button" className="sp-text-btn" onClick={copyText}>{copyStatus === 'Copied' ? <Check size={15} /> : <Clipboard size={15} />} {copyStatus === 'Copied' ? 'Copied' : 'Copy text'}</button>
      </div>
      <pre className="sp-redacted">{result.redacted_text}</pre>
      <span role="status" className={copyStatus === 'Copied' ? 'sp-sr-only' : 'sp-help'}>{copyStatus}</span>
    </div>
  )
}

export default function Scanner({ type, onScan }: { type: ScanType; onScan: () => void }) {
  const config = scanners[type]
  const Icon = config.icon
  const [value, setValue] = useState('')
  const [error, setError] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [busy, setBusy] = useState(false)
  const request = useRef<AbortController | null>(null)
  useEffect(() => () => request.current?.abort(), [])

  function edit(nextValue: string) {
    setValue(nextValue)
    setError('')
    setResult(null)
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (request.current) return
    if (!value.trim()) {
      setError('Enter ' + (type === 'url' ? 'a website address' : 'some text') + ' to scan.')
      return
    }
    if (type === 'url' && !/^https?:\/\//i.test(value.trim())) {
      setError('Start the address with http:// or https://.')
      return
    }
    const controller = new AbortController()
    request.current = controller
    setBusy(true)
    setError('')
    setResult(null)
    try {
      const nextResult = await runScan(type, value, controller.signal)
      if (!controller.signal.aborted) {
        setResult(nextResult)
        onScan()
      }
    } catch (err) {
      if (!controller.signal.aborted) setError(err instanceof Error ? err.message : 'Scan failed. Try again.')
    } finally {
      request.current = null
      if (!controller.signal.aborted) setBusy(false)
    }
  }

  return (
    <section className={'sp-page sp-' + type}>
      <header className="sp-page-heading"><h1>{config.name}</h1><p>{config.intro}</p></header>
      <div className="sp-workbench">
        <div className="sp-input-column">
          <form className="sp-surface" onSubmit={submit}>
            <div className="sp-panel-head"><span className="sp-icon-tile"><Icon size={21} /></span><h2>Scan input</h2></div>
            <div className="sp-form-body">
              <div className="sp-input-label"><label htmlFor="scan-value">{config.label}</label>
                <button className="sp-text-btn" type="button" onClick={() => edit(config.sample)} disabled={busy}><FlaskConical size={14} /> Use sample</button>
              </div>
              {type === 'url'
                ? <input id="scan-value" type="url" value={value} placeholder={config.placeholder} readOnly={busy} onChange={e => edit(e.target.value)} autoComplete="off" spellCheck={false} aria-describedby="sp-hint" required />
                : <textarea id="scan-value" rows={8} value={value} placeholder={config.placeholder} readOnly={busy} onChange={e => edit(e.target.value)} autoComplete="off" spellCheck={false} aria-describedby="sp-hint" required />}
              <p id="sp-hint" className="sp-help">{config.helper}</p>
              {error && <p className="sp-error" role="alert">{error}</p>}
              <button type="submit" className="sp-primary" disabled={busy}>{busy ? <LoaderCircle className="sp-spin" size={17} /> : <ScanLine size={17} />} {busy ? 'Scanning…' : config.action}</button>
            </div>
            <div className="sp-footnote"><LockKeyhole size={14} /> Only scan metadata is saved in history.</div>
          </form>
          <aside className="sp-method"><span className="sp-meta">Detection method</span><h3>{config.method}</h3><p>{config.how}</p></aside>
        </div>
        <section className="sp-surface sp-output" aria-label="Scan result" aria-busy={busy}>
          <div className="sp-panel-head"><ScanLine size={19} className="sp-accent" /><h2>Scan result</h2></div>
          <span role="status" className="sp-sr-only">{busy ? 'Scan in progress.' : result ? 'Scan complete. ' + result.prediction + '.' : ''}</span>
          {result
            ? type === 'privacy' ? <PrivacyResult result={result} /> : <ModelResult result={result} type={type} />
            : <div className="sp-await"><ScannerArt type={type} /><h3>{busy ? 'Scanning input…' : 'Awaiting scan'}</h3>
                <p>{type === 'privacy' ? 'Detected categories and a redacted copy will appear here.' : 'The model prediction and phishing probability will appear here.'}</p></div>}
        </section>
      </div>
    </section>
  )
}
