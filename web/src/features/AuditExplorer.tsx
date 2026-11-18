import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { useAudit, useCheckpoints, useOverview } from '../api/hooks'
import type { AuditEvent } from '../api/types'
import { ChainRibbon } from '../components/ChainRibbon'
import { DecisionTrace } from '../components/DecisionTrace'
import { Badge, Drawer, Empty, Panel, Skeleton, shortHash, timeLabel } from '../components/ui'

const EVENT_TYPES = [
  '', 'REQUEST_RECEIVED', 'PRINCIPAL_RESOLVED', 'PRINCIPAL_REJECTED', 'INPUT_INSPECTED',
  'INTENT_CREATED', 'TOOL_CALL_PROPOSED', 'POLICY_EVALUATED', 'APPROVAL_REQUESTED',
  'APPROVAL_DECIDED', 'APPROVAL_CONSUMED', 'TOOL_EXECUTION_STARTED',
  'TOOL_EXECUTION_COMPLETED', 'OUTPUT_INSPECTED', 'RESPONSE_RELEASED',
  'RESPONSE_SUPPRESSED', 'SECURITY_ALERT_RAISED',
]

export function AuditExplorer() {
  const [params, setParams] = useSearchParams()
  const [selected, setSelected] = useState<AuditEvent | null>(null)
  const [page, setPage] = useState(0)
  const query = params.get('request') ?? ''
  const type = params.get('type') ?? ''
  const decision = params.get('decision') ?? ''
  const principal = params.get('principal') ?? ''

  const filterString = useMemo(() => {
    const search = new URLSearchParams({ limit: '100', offset: String(page * 100) })
    if (query) search.set('request_id', query)
    if (type) search.set('event_type', type)
    if (decision) search.set('decision', decision)
    if (principal) search.set('principal', principal)
    return search.toString()
  }, [query, type, decision, page, principal])

  const audit = useAudit(filterString)
  const checkpoints = useCheckpoints()
  const overview = useOverview()
  const correlation = useQuery({
    queryKey: ['correlation', selected?.request_id],
    queryFn: () => api.correlate(selected?.request_id ?? ''),
    enabled: Boolean(selected?.request_id),
  })

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next)
    setPage(0)
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Audit Explorer</h1>
          <p>Read-only evidence. Redacted fields only — no raw payloads or content.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone="info">{audit.data?.total ?? 0} events</Badge>
      </div>

      <div className="filters">
        <div className="field">
          <label htmlFor="req">Request ID</label>
          <input id="req" value={query} onChange={(event) => setFilter('request', event.target.value)} placeholder="req-…" />
        </div>
        <div className="field">
          <label htmlFor="type">Event type</label>
          <select id="type" value={type} onChange={(event) => setFilter('type', event.target.value)}>
            {EVENT_TYPES.map((item) => (
              <option key={item} value={item}>{item || 'All events'}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="decision">Decision</label>
          <select id="decision" value={decision} onChange={(event) => setFilter('decision', event.target.value)}>
            <option value="">All decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="ASK_USER">ASK_USER</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="principal">Principal</label>
          <input id="principal" value={principal} onChange={(event) => setFilter('principal', event.target.value)} placeholder="subject id" />
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Events</span>
          <span className="topbar-spacer" />
          <button className="btn ghost" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>← Previous</button>
          <button className="btn ghost" disabled={!audit.data?.has_more} onClick={() => setPage((value) => value + 1)}>Next →</button>
        </div>
        {audit.isLoading ? <Skeleton rows={10} /> : audit.data?.items.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Request</th>
                  <th>Tool / Action</th>
                  <th>Decision</th>
                  <th>Reason</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {audit.data.items.map((event) => (
                  <tr key={event.sequence_number} onClick={() => setSelected(event)}>
                    <td className="mono">{event.sequence_number}</td>
                    <td className="faint" style={{ fontSize: 11 }}>{timeLabel(event.occurred_at)}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{event.event_type}</td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{shortHash(event.request_id)}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{event.tool_id ? `${event.tool_id}.${event.action_id ?? ''}` : '—'}</td>
                    <td>
                      {event.decision ? (
                        <Badge tone={event.decision === 'BLOCK' ? 'bad' : event.decision === 'ALLOW' ? 'ok' : 'warn'}>{event.decision}</Badge>
                      ) : <span className="faint">—</span>}
                    </td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{event.reason ?? '—'}</td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{shortHash(event.event_hash)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No matching events" hint="Change the filters or wait for signed requests to produce audit evidence." />
        )}
      </div>

      <Drawer
        open={selected !== null}
        onOpenChange={(open) => !open && setSelected(null)}
        title={`Event #${selected?.sequence_number ?? ''}`}
        subtitle={selected?.event_type ?? ''}
      >
        {selected ? (
          <div>
            <h3>Decision trace</h3>
            <DecisionTrace events={correlation.data?.events ?? [selected]} />
            <h3 style={{ marginTop: 8 }}>Chain ribbon</h3>
            <ChainRibbon
              events={correlation.data?.events ?? [selected]}
              checkpoints={checkpoints.data ?? []}
              headSequence={overview.data?.chain_head_sequence ?? 0}
            />
            <h3 style={{ marginTop: 8 }}>Redacted event fields</h3>
            <dl className="kv">
              <dt>Sequence</dt><dd>{selected.sequence_number}</dd>
              <dt>Occurred</dt><dd>{timeLabel(selected.occurred_at)}</dd>
              <dt>Event type</dt><dd>{selected.event_type ?? '—'}</dd>
              <dt>Component</dt><dd>{selected.component ?? '—'}</dd>
              <dt>Request ID</dt><dd>{selected.request_id ?? '—'}</dd>
              <dt>Call ID</dt><dd>{selected.call_id ?? '—'}</dd>
              <dt>Principal</dt><dd>{selected.principal_subject_id ?? '—'}</dd>
              <dt>Tool / action</dt><dd>{selected.tool_id ?? '—'} / {selected.action_id ?? '—'}</dd>
              <dt>Decision / reason</dt><dd>{selected.decision ?? '—'} / {selected.reason ?? '—'}</dd>
              <dt>Outcome</dt><dd>{selected.outcome ?? '—'}</dd>
              <dt>Destination</dt><dd>{selected.destination ?? '—'}</dd>
              <dt>Risk score</dt><dd>{selected.risk_score ?? '—'}</dd>
              <dt>Policy</dt><dd>{selected.policy_version ?? '—'} · {shortHash(selected.policy_hash)}</dd>
              <dt>Evidence</dt><dd>DLP: {selected.has_dlp_evidence ? 'yes' : 'no'} · Input: {selected.has_input_evidence ? 'yes' : 'no'} · Resources: {selected.resource_count}</dd>
              <dt>Event hash</dt><dd>{selected.event_hash}</dd>
              <dt>Previous hash</dt><dd>{selected.previous_hash}</dd>
            </dl>
            {correlation.data?.events && correlation.data.events.length > 1 ? (
              <Panel title={`Correlated events (${correlation.data.events.length})`}>
                <div style={{ display: 'grid', gap: 4 }}>
                  {correlation.data.events.map((event) => (
                    <button
                      key={event.sequence_number}
                      className="rail-link"
                      style={{ justifyContent: 'flex-start', background: 'transparent' }}
                      onClick={() => setSelected(event)}
                    >
                      <span className="mono" style={{ fontSize: 11 }}>#{event.sequence_number}</span>
                      <span className="mono faint" style={{ fontSize: 11 }}>{event.event_type}</span>
                    </button>
                  ))}
                </div>
              </Panel>
            ) : null}
            {selected.destination ? (
              <p className="notice readonly">Destination is a canonical label only — no raw URL content is displayed.</p>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  )
}
