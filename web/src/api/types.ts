export type Role = 'admin' | 'analyst' | 'approver' | 'operator' | 'developer' | 'viewer'

export interface SessionInfo {
  csrf_token: string
  username: string
  role: Role
  tenant_id: string | null
  permissions: string[]
  expires_at: string
}

export interface HealthItem {
  name: string
  state: 'healthy' | 'degraded' | 'unavailable'
  detail: string
}

export interface Overview {
  generated_at: string
  chain_id: string
  chain_head_sequence: number
  chain_head_hash: string
  last_checkpoint_seal: string | null
  event_count: number
  alert_count: number
  pending_approval_count: number
  verified_event_count: number
  health: HealthItem[]
  policy_version: string
  policy_hash: string
  live: boolean
}

export interface AuditEvent {
  sequence_number: number
  occurred_at: string | null
  event_type: string | null
  component: string | null
  request_id: string | null
  trace_id: string | null
  call_id: string | null
  decision: string | null
  reason: string | null
  outcome: string | null
  tool_id: string | null
  action_id: string | null
  principal_subject_id: string | null
  destination: string | null
  risk_score: number | null
  policy_version: string | null
  policy_hash: string | null
  event_hash: string
  previous_hash: string
  has_dlp_evidence: boolean
  has_input_evidence: boolean
  resource_count: number
  result_bytes: number | null
  duration_ms: number | null
}

export interface AuditPage {
  items: AuditEvent[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

export interface AuditCorrelation {
  events: AuditEvent[]
  by_request: Record<string, number[]>
}

export interface Verification {
  verified: boolean
  chain_id: string
  event_count: number
  head_sequence: number | null
  head_hash: string | null
  failure_codes: string[]
  failures_truncated: boolean
}

export interface Alert {
  sequence_number: number
  occurred_at: string
  rule_id: string
  severity: string
  count: number
  window_seconds: number
  evidence: string[]
  request_id: string
  triage_status: string
  triage_note: string | null
  assignee: string | null
  hypothesis: string | null
}

export interface AlertRule {
  rule_id: string
  kind: string
  window_seconds: number
  threshold: number
  severity: string
  enabled: boolean
  description: string
}

export interface AlertRules {
  version: string
  rules: AlertRule[]
}

export interface Approval {
  approval_id: string
  request_id: string
  tenant_id: string | null
  requester_subject_id: string
  tool_id: string
  action_id: string
  status: string
  required_approver_rule: string
  expires_at: string
  created_at: string
  resource_count: number
  destination: string | null
  risk_score: number
  policy_version: string
  policy_hash: string
  self_approval_allowed: boolean
  decided_by_subject_id: string | null
}

export interface Tool {
  tool_id: string
  action_id: string
  side_effect_class: string
  data_class: string
  enabled_in_policy: boolean
  external_destinations: string[]
  timeout_seconds: number | null
  max_concurrency: number | null
}

export interface Connector {
  connector_id: string
  name: string
  status: string
  requires_network: boolean
  egress_destination_count: number
  permission_count: number
  secret_ref_digest: string | null
  enabled_at: string | null
}

export interface Policy {
  version: string
  combined_hash: string
  tools: Tool[]
  thresholds: Record<string, number>
  self_checks: string[]
}

export interface ConfigView {
  name: string
  version: string
  summary: Record<string, unknown>
}

export interface Limiter {
  window_seconds: number
  buckets: string[]
  store_kind: string
  shared: boolean
  caveat: string
}

export interface Checkpoint {
  sequence_number: number
  head_hash: string
  previous_seal: string | null
  seal: string
  occurred_at: string
  verified: boolean
}

export interface Setting {
  key: string
  value: string
  sensitive: boolean
  restart_required: boolean
}

export interface EvaluationReport {
  name: string
  generated_at: string | null
  cases: number | null
  summary: Record<string, unknown>
}

export interface User {
  username: string
  role: Role
  tenant_id: string | null
}

export interface WriteResult {
  ok: boolean
  message: string
  id: string | null
}
