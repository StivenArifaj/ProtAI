import type { AuditEvent } from '../api/types'

const STAGES = [
  { id: 'INGRESS', types: ['REQUEST_RECEIVED', 'PRINCIPAL_RESOLVED', 'PRINCIPAL_REJECTED'] },
  { id: 'INPUT', types: ['INPUT_INSPECTED'] },
  { id: 'INTENT', types: ['INTENT_CREATED', 'INTENT_FAILED'] },
  { id: 'POLICY', types: ['TOOL_CALL_PROPOSED', 'POLICY_EVALUATED'] },
  {
    id: 'APPROVAL',
    types: ['APPROVAL_REQUESTED', 'APPROVAL_DECIDED', 'APPROVAL_CONSUMED', 'APPROVAL_EXPIRED'],
  },
  {
    id: 'GATEWAY',
    types: ['TOOL_EXECUTION_STARTED', 'TOOL_EXECUTION_COMPLETED', 'TOOL_EXECUTION_FAILED'],
  },
  {
    id: 'DLP',
    types: ['EGRESS_INSPECTED', 'OUTPUT_INSPECTED', 'RESPONSE_RELEASED', 'RESPONSE_SUPPRESSED'],
  },
  { id: 'AUDIT', types: ['SECURITY_ALERT_RAISED'] },
] as const

function stageState(events: AuditEvent[], types: readonly string[]) {
  const matched = events.filter((event) => types.includes(event.event_type ?? ''))
  if (matched.length === 0) {
    return { state: 'pending', event: null } as const
  }
  if (matched.some((event) => event.decision === 'BLOCK' || event.outcome === 'DENIED')) {
    return { state: 'blocked', event: matched[0] } as const
  }
  if (matched.some((event) => event.decision === 'ALLOW')) {
    return { state: 'allowed', event: matched[0] } as const
  }
  return { state: 'reached', event: matched[0] } as const
}

const STATE_TEXT: Record<string, string> = {
  pending: '—',
  reached: 'seen',
  blocked: 'BLOCK',
  allowed: 'ALLOW',
}

export function DecisionTrace({
  events,
  onSelect,
}: {
  events: AuditEvent[]
  onSelect?: (event: AuditEvent) => void
}) {
  return (
    <div className="trace" aria-label="Decision trace">
      {STAGES.map((stage, index) => {
        const { state, event } = stageState(events, stage.types)
        return (
          <div key={stage.id} style={{ display: 'contents' }}>
            {index > 0 ? <div className="trace-connector" aria-hidden="true" /> : null}
            <button
              type="button"
              className={`trace-node ${state}`}
              disabled={!event || !onSelect}
              onClick={() => event && onSelect?.(event)}
              title={event ? `Event #${event.sequence_number}` : 'No event recorded'}
              aria-label={`${stage.id}: ${STATE_TEXT[state]}`}
            >
              <div className="trace-node-label">{stage.id}</div>
              <div className="trace-node-state">{STATE_TEXT[state]}</div>
            </button>
          </div>
        )
      })}
    </div>
  )
}
