import { useMemo, useState } from 'react'
import { useLiveStream } from '../api/hooks'
import { useLogServices, useLogs, useMetrics } from '../api/hooks'
import { Badge, Empty, Panel, Skeleton, timeLabel } from '../components/ui'
import { useLive } from '../state/live'

const LEVELS = ['', 'INFO', 'NOTICE', 'WARN', 'ERROR', 'ALERT']

function levelTone(level: string): 'ok' | 'warn' | 'bad' | 'info' {
  if (level === 'ERROR' || level === 'ALERT') return 'bad'
  if (level === 'WARN') return 'warn'
  if (level === 'NOTICE') return 'info'
  return 'ok'
}

export function Logs() {
  const [service, setService] = useState('')
  const [level, setLevel] = useState('')
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(250)
  const { paused } = useLive()
  const live = useLiveStream(paused)
  const params = useMemo(
    () =>
      new URLSearchParams({
        limit: String(limit),
        ...(service ? { service } : {}),
        ...(level ? { level } : {}),
        ...(search ? { q: search } : {}),
      }).toString(),
    [service, level, search, limit],
  )
  const logs = useLogs(params, !paused)
  const services = useLogServices()
  const metrics = useMetrics()

  const bars = metrics.data?.event_types.slice(0, 12) ?? []
  const maxBar = Math.max(1, ...bars.map((item) => item.count))

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Logs</h1>
          <p>Unified read-only view of audit events and runtime logs. Filter by service, severity, or text.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone={paused ? 'warn' : 'ok'}>{paused ? 'paused' : `live · ${logs.data?.length ?? 0} lines`}</Badge>
      </div>

      <Panel title="Volume by event type" actions={<Badge tone="info">real audit data · last {metrics.data?.window_events ?? 0}</Badge>}>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, height: 90, overflowX: 'auto' }}>
          {bars.length ? (
            bars.map((bar) => (
              <div
                key={bar.name}
                title={`${bar.name}: ${bar.count}`}
                style={{
                  width: 44,
                  flex: 'none',
                  background: 'var(--accent-bg)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: '3px 3px 0 0',
                  height: `${Math.max(4, (bar.count / maxBar) * 80)}px`,
                }}
              />
            ))
          ) : (
            <span className="faint" style={{ fontSize: 12 }}>No events yet</span>
          )}
        </div>
        <div className="faint" style={{ fontSize: 11, marginTop: 4 }}>
          {bars.map((bar) => bar.name).slice(0, 6).join(' · ') || '—'}
        </div>
      </Panel>

      <div className="filters" style={{ marginTop: 16 }}>
        <div className="field">
          <label htmlFor="service">Service</label>
          <select id="service" value={service} onChange={(event) => setService(event.target.value)}>
            <option value="">All services</option>
            {(services.data ?? []).map((item) => (
              <option key={item.service} value={item.service}>
                {item.service} ({item.count})
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="level">Severity</label>
          <select id="level" value={level} onChange={(event) => setLevel(event.target.value)}>
            {LEVELS.map((item) => <option key={item} value={item}>{item || 'All levels'}</option>)}
          </select>
        </div>
        <div className="field" style={{ flex: 1, minWidth: 200 }}>
          <label htmlFor="search">Search message</label>
          <input id="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="BLOCK, request id, tool…" />
        </div>
        <div className="field">
          <label htmlFor="limit">Lines</label>
          <select id="limit" value={limit} onChange={(event) => setLimit(Number(event.target.value))}>
            {[100, 250, 500, 1000].map((value) => <option key={value}>{value}</option>)}
          </select>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Log stream</span>
          <span className="topbar-spacer" />
          <span className="faint mono" style={{ fontSize: 11 }}>
            {live.lastAlertCount ?? 0} alerts in chain · {metrics.data?.avg_risk_score.toFixed(1) ?? '—'} avg risk
          </span>
        </div>
        {logs.isLoading ? <Skeleton rows={12} /> : logs.data?.length ? (
          <div className="table-wrap">
            <table className="data log-table">
              <thead>
                <tr><th>Time</th><th>Service</th><th>Level</th><th>Message</th><th>Source</th></tr>
              </thead>
              <tbody>
                {logs.data.map((entry) => (
                  <tr key={entry.id} style={{ cursor: 'default' }}>
                    <td className="mono faint" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                      {timeLabel(entry.occurred_at)}
                    </td>
                    <td><Badge tone="info">{entry.service}</Badge></td>
                    <td><Badge tone={levelTone(entry.level)}>{entry.level}</Badge></td>
                    <td className="mono log-message" title={entry.message}>{entry.message}</td>
                    <td className="faint" style={{ fontSize: 11 }}>{entry.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No log lines" hint="Adjust the filters or generate traffic with scripts/demo_request.py." />
        )}
      </div>
    </div>
  )
}
