export interface LogEntry {
  id: string
  occurred_at: string | null
  service: string
  level: string
  message: string
  source: 'audit' | 'runtime'
  sequence_number: number | null
}

export interface LogServiceCount {
  service: string
  count: number
}

export interface MetricRow {
  name: string
  count: number
}

export interface Metrics {
  window_events: number
  decisions: MetricRow[]
  event_types: MetricRow[]
  top_tools: MetricRow[]
  avg_risk_score: number
  alerts_per_100_events: number
  chain_verified: boolean
  source: string
}
