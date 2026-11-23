export type ScanType = 'url' | 'email' | 'privacy'

export interface ScanRecord {
  id: number
  timestamp: string
  scan_type: ScanType
  prediction: string
  risk_level: string
  findings: string
}

export interface HistoryResponse {
  items: ScanRecord[]
  total: number
  total_scans: number
  phishing_detections: number
  privacy_matches: number
  daily_activity: { date: string; count: number }[]
}

type Counts = { emails: number; phone_numbers: number; aadhaar_numbers: number }

export interface ScanResult {
  prediction: string
  risk_level: string
  phishing_probability?: number | null
  reason?: string
  features?: Record<string, number>
  counts?: Counts
  redacted_text?: string
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch('/api' + path, options)
  } catch (error) {
    if (options?.signal?.aborted) throw error
    throw new Error('Could not reach SentinelAI. Check that the local API is running.')
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    if (typeof body?.detail === 'string') throw new Error(body.detail)
    if (response.status === 422) throw new Error('Check your input and try again.')
    throw new Error('The API could not complete this request. Check the connection and try again.')
  }
  return response.json() as Promise<T>
}

export function getHealth(signal?: AbortSignal) {
  return request<{ status: string }>('/health', { signal })
}

interface HistoryOptions {
  scanType?: ScanType
  limit?: number
  offset?: number
  signal?: AbortSignal
}

export function getHistory({ scanType, limit = 10, offset = 0, signal }: HistoryOptions = {}) {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  if (scanType) query.set('scan_type', scanType)
  return request<HistoryResponse>('/history?' + query, { signal })
}

export function runScan(type: ScanType, value: string, signal: AbortSignal) {
  const path = type === 'privacy' ? '/privacy/redact' : '/scan/' + type
  const body = type === 'url' ? { url: value.trim() } : { text: value }
  return request<ScanResult>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  })
}
