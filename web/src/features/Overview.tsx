import { useNavigate } from 'react-router-dom'
import { useAlerts, useAudit, useCheckpoints, useLiveStream, useOverview } from '../api/hooks'
import { ChainRibbon } from '../components/ChainRibbon'
import { Badge, Empty, Panel, Skeleton, Stat, shortHash, timeLabel } from '../components/ui'
import { useLive } from '../state/live'

function stateTone(state: string): 'ok' | 'bad' | 'warn' {
  return state === 'healthy' ? 'ok' : state === 'unavailable' ? 'bad' : 'warn'
}

export function Overview() {
  const overview = useOverview()
  const alerts = useAlerts()
  const audit = useAudit('limit=12')
  const checkpoints = useCheckpoints()
  const navigate = useNavigate()
  const { paused } = useLive()
  const live = useLiveStream(paused)

  if (overview.isLoading) return <Skeleton rows={8} />

  const data = overview.data

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Security overview</h1>
          <p>Live posture of the enforcement plane, audit chain, and monitoring rules.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone={paused ? 'warn' : 'ok'}>{paused ? 'stream paused' : 'live'}</Badge>
      </div>

      <div className="grid-stats">
        <Stat label="Audit events" value={data?.event_count ?? '—'} note={`chain ${data?.chain_id ?? '—'}`} />
        <Stat
          label="Open alerts"
          value={data?.alert_count ?? '—'}
          note="deterministic rules only"
        />
        <Stat
          label="Pending approvals"
          value={data?.pending_approval_count ?? '—'}
          note="human decisions required"
        />
        <Stat
          label="Chain head"
          value={`#${data?.chain_head_sequence ?? '—'}`}
          note={shortHash(data?.chain_head_hash)}
        />
      </div>

      <div className="two-col">
        <Panel title="Integration health" actions={<Badge tone="info">{data?.health.length ?? 0} checks</Badge>}>
          <div style={{ display: 'grid', gap: 6 }}>
            {data?.health.map((item) => (
              <div
                key={item.name}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '6px 8px',
                  borderBottom: '1px solid var(--border)',
                  flexWrap: 'wrap',
                }}
              >
                <span style={{ flex: '0 0 110px', fontWeight: 600 }}>{item.name}</span>
                <Badge tone={stateTone(item.state)}>{item.state}</Badge>
                <span className="muted" style={{ fontSize: 12, minWidth: 0, overflowWrap: 'anywhere' }}>{item.detail}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Audit chain ribbon" actions={<span className="faint mono" style={{ fontSize: 11 }}>last 48 events</span>}>
          <ChainRibbon
            events={audit.data?.items ?? []}
            checkpoints={checkpoints.data ?? []}
            headSequence={data?.chain_head_sequence ?? 0}
          />
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            Truncation of the newest events is undetectable without an external anchor.
            Last checkpoint: {shortHash(data?.last_checkpoint_seal)}.
          </p>
        </Panel>
      </div>

      <div className="two-col equal" style={{ marginTop: 16 }}>
        <Panel
          title="Alerts needing attention"
          actions={
            <button className="btn ghost" onClick={() => navigate('/alerts')}>
              Open queue →
            </button>
          }
        >
          {alerts.data?.length ? (
            <div style={{ display: 'grid', gap: 6 }}>
              {alerts.data.slice(0, 8).map((alert) => (
                <button
                  key={alert.sequence_number}
                  className="rail-link"
                  style={{ width: '100%', justifyContent: 'flex-start', background: 'transparent' }}
                  onClick={() => navigate(`/alerts?event=${alert.sequence_number}`)}
                >
                  <Badge tone={alert.severity === 'HIGH' ? 'bad' : 'warn'}>{alert.severity}</Badge>
                  <span className="mono" style={{ fontSize: 12 }}>{alert.rule_id}</span>
                  <span className="topbar-spacer" />
                  <span className="faint">{alert.count} hits</span>
                </button>
              ))}
            </div>
          ) : (
            <Empty title="No alerts in the chain" hint="Deterministic rules emit content-free evidence here when they fire." />
          )}
        </Panel>

        <Panel title="Recent decisions" actions={<button className="btn ghost" onClick={() => navigate('/audit')}>Explore →</button>}>
          {audit.data?.items.length ? (
            <table className="data">
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Decision</th>
                </tr>
              </thead>
              <tbody>
                {audit.data.items.slice(0, 8).map((event) => (
                  <tr key={event.sequence_number} onClick={() => navigate(`/audit?request=${event.request_id ?? ''}`)}>
                    <td className="mono">{event.sequence_number}</td>
                    <td className="faint" style={{ fontSize: 12 }}>{timeLabel(event.occurred_at)}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{event.event_type}</td>
                    <td>
                      {event.decision ? (
                        <Badge tone={event.decision === 'BLOCK' ? 'bad' : event.decision === 'ALLOW' ? 'ok' : 'warn'}>
                          {event.decision}
                        </Badge>
                      ) : (
                        <span className="faint">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty title="No audit events yet" hint="Events appear here after signed requests flow through the gateway." />
          )}
        </Panel>
      </div>

      <p className="faint" style={{ fontSize: 12, marginTop: 14 }}>
        Live stream: {paused ? 'paused' : 'connected'} · last alert snapshot: {live.lastAlertCount ?? '—'} ·
        policy {data?.policy_version} · {shortHash(data?.policy_hash)}
      </p>
    </div>
  )
}
