import type {
  Alert,
  AlertRules,
  Approval,
  AuditCorrelation,
  AuditPage,
  Checkpoint,
  ConfigView,
  Connector,
  EvaluationReport,
  Limiter,
  Overview,
  Policy,
  SessionInfo,
  Setting,
  Tool,
  User,
  Verification,
  WriteResult,
} from './types'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

let csrfToken: string | null = null

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  }
  if (options.method && options.method !== 'GET') {
    const token = csrfToken ?? readSessionCookie()
    if (token) headers['X-Console-CSRF'] = token
  }
  const response = await fetch(`/admin${path}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  })
  if (!response.ok) {
    let message = response.statusText
    try {
      const body = (await response.json()) as { detail?: string }
      if (typeof body.detail === 'string') message = body.detail
    } catch {
      // keep status text
    }
    throw new ApiError(response.status, message)
  }
  return (await response.json()) as T
}

function readSessionCookie(): string | null {
  const match = document.cookie.match(/protai_console_session=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : null
}

export const api = {
  login: async (username: string, password: string): Promise<SessionInfo> => {
    const result = await request<SessionInfo>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    })
    csrfToken = result.csrf_token
    return result
  },
  logout: () => request<WriteResult>('/auth/logout', { method: 'POST' }),
  session: async (): Promise<SessionInfo> => {
    const result = await request<SessionInfo>('/meta/session')
    csrfToken = result.csrf_token
    return result
  },
  overview: () => request<Overview>('/overview'),
  audit: (params: URLSearchParams) => request<AuditPage>(`/audit/events?${params}`),
  correlate: (requestId: string) =>
    request<AuditCorrelation>(`/audit/correlate?request_id=${encodeURIComponent(requestId)}`),
  verify: () => request<Verification>('/audit/verify'),
  checkpoints: () => request<Checkpoint[]>('/audit/checkpoints'),
  sealCheckpoint: () => request<WriteResult>('/audit/checkpoints', { method: 'POST' }),
  alerts: () => request<Alert[]>('/alerts'),
  alertRules: () => request<AlertRules>('/alerts/rules'),
  triage: (sequence: number, body: { status: string; note: string; assignee: string | null }) =>
    request<WriteResult>(`/alerts/triage/${sequence}`, { method: 'POST', body: JSON.stringify(body) }),
  summarize: (alert_sequence: number) =>
    request<WriteResult>('/alerts/summarize', { method: 'POST', body: JSON.stringify({ alert_sequence }) }),
  approvals: () => request<Approval[]>('/approvals'),
  decide: (id: string, approval_token: string, approve: boolean) =>
    request<WriteResult>(`/approvals/${encodeURIComponent(id)}/decide`, {
      method: 'POST',
      body: JSON.stringify({ approval_token, approve }),
    }),
  revoke: (id: string, reason: string) =>
    request<WriteResult>(`/approvals/${encodeURIComponent(id)}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  tools: () => request<Tool[]>('/tools'),
  connectors: () => request<Connector[]>('/connectors'),
  enableConnector: (id: string, threat_review_id: string) =>
    request<WriteResult>(`/connectors/${encodeURIComponent(id)}/enable`, {
      method: 'POST',
      body: JSON.stringify({ threat_review_id }),
    }),
  disableConnector: (id: string) =>
    request<WriteResult>(`/connectors/${encodeURIComponent(id)}/disable`, { method: 'POST' }),
  policy: () => request<Policy>('/policies'),
  configs: () => request<ConfigView[]>('/configs'),
  limiter: () => request<Limiter>('/limiter'),
  settings: () => request<Setting[]>('/settings'),
  reports: () => request<EvaluationReport[]>('/evaluation/reports'),
  users: () => request<User[]>('/auth/users'),
  createUser: (body: { username: string; password: string; role: string }) =>
    request<WriteResult>('/auth/users', { method: 'POST', body: JSON.stringify(body) }),
}
