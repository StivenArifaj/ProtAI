import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { useAlerts, useInvalidate, useRules } from '../api/hooks'
import type { Alert } from '../api/types'
import { Badge, Drawer, Empty, Panel, Skeleton, useToast } from '../components/ui'

export function Alerts() {
  const alerts = useAlerts()
  const rules = useRules()
  const invalidate = useInvalidate()
  const toast = useToast()
  const [selected, setSelected] = useState<Alert | null>(null)
  const [params, setParams] = useSearchParams()
  const [note, setNote] = useState('')
  const [status, setStatus] = useState('acknowledged')
  const [assignee, setAssignee] = useState('')
  const [busy, setBusy] = useState(false)

  const severity = params.get('severity') ?? ''
  const filtered = (alerts.data ?? []).filter(
    (alert) => !severity || alert.severity === severity,
  )

  const openAlert = (alert: Alert) => {
    setSelected(alert)
    setNote(alert.triage_note ?? '')
    setStatus(alert.triage_status === 'new' ? 'acknowledged' : alert.triage_status)
    setAssignee(alert.assignee ?? '')
  }

  const saveTriage = async () => {
    if (!selected) return
    setBusy(true)
    try {
      const result = await api.triage(selected.sequence_number, {
        status,
        note,
        assignee: assignee || null,
      })
      toast(result.message, result.ok)
      invalidate()
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Triage failed', false)
    } finally {
      setBusy(false)
    }
  }

  const summarize = async () => {
    if (!selected) return
    setBusy(true)
    try {
      const result = await api.summarize(selected.sequence_number)
      toast(result.message, result.ok)
      invalidate()
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Summarizer failed', false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Alerts & triage</h1>
          <p>Deterministic alerts are evidence only. No containment or execution is possible here.</p>
        </div>
        <span className="topbar-spacer" />
        <select
          className="btn"
          value={severity}
          onChange={(event) => {
            const next = new URLSearchParams(params)
            if (event.target.value) next.set('severity', event.target.value)
            else next.delete('severity')
            setParams(next)
          }}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="CRITICAL">CRITICAL</option>
        </select>
      </div>

      <div className="notice readonly">
        <strong>Read-only by design.</strong> Alerts cannot block, allow, revoke, or contain.
        Triage notes are local annotations, not security decisions.
      </div>

      <div className="grid-stats">
        <div className="stat">
          <div className="stat-label">Total alerts</div>
          <div className="stat-value">{alerts.data?.length ?? '—'}</div>
        </div>
        <div className="stat">
          <div className="stat-label">High severity</div>
          <div className="stat-value">{filtered.filter((item) => item.severity === 'HIGH').length}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Untriaged</div>
          <div className="stat-value">{filtered.filter((item) => item.triage_status === 'new').length}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Active rules</div>
          <div className="stat-value">{rules.data?.rules.filter((rule) => rule.enabled).length ?? '—'}</div>
          <div className="stat-note">config {rules.data?.version}</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><span className="panel-title">Alert queue</span></div>
        {alerts.isLoading ? <Skeleton rows={8} /> : filtered.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>#</th><th>Time</th><th>Severity</th><th>Rule</th><th>Count</th><th>Evidence</th><th>Status</th><th>Assignee</th></tr>
              </thead>
              <tbody>
                {filtered.map((alert) => (
                  <tr key={alert.sequence_number} onClick={() => openAlert(alert)}>
                    <td className="mono">{alert.sequence_number}</td>
                    <td className="faint" style={{ fontSize: 11 }}>{new Date(alert.occurred_at).toLocaleString()}</td>
                    <td><Badge tone={alert.severity === 'HIGH' || alert.severity === 'CRITICAL' ? 'bad' : 'warn'}>{alert.severity}</Badge></td>
                    <td className="mono" style={{ fontSize: 11 }}>{alert.rule_id}</td>
                    <td className="mono">{alert.count}</td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{alert.evidence.join(', ') || '—'}</td>
                    <td><Badge tone={alert.triage_status === 'resolved' ? 'ok' : 'info'}>{alert.triage_status}</Badge></td>
                    <td className="faint">{alert.assignee ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No alerts" hint="Deterministic rules emit content-free alerts into the audit chain when thresholds are exceeded." />
        )}
      </div>

      <div style={{ marginTop: 16 }}>
        <Panel title="Rule configuration" actions={<Badge tone="info">v{rules.data?.version ?? '—'}</Badge>}>
          {rules.data?.rules.length ? (
            <table className="data">
              <thead><tr><th>Rule</th><th>Kind</th><th>Window</th><th>Threshold</th><th>Severity</th><th>Enabled</th></tr></thead>
              <tbody>
                {rules.data.rules.map((rule) => (
                  <tr key={rule.rule_id} style={{ cursor: 'default' }}>
                    <td className="mono" style={{ fontSize: 11 }}>{rule.rule_id}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{rule.kind}</td>
                    <td className="mono">{rule.window_seconds}s</td>
                    <td className="mono">{rule.threshold}</td>
                    <td>{rule.severity}</td>
                    <td><Badge tone={rule.enabled ? 'ok' : 'warn'}>{rule.enabled ? 'enabled' : 'disabled'}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty title="No rule config" hint="Alert rules are read from the strict configuration file." />}
        </Panel>
      </div>

      <Drawer
        open={selected !== null}
        onOpenChange={(open) => !open && setSelected(null)}
        title="Alert detail"
        subtitle={selected ? `event #${selected.sequence_number} · ${selected.rule_id}` : undefined}
      >
        {selected ? (
          <div>
            <dl className="kv">
              <dt>Severity</dt><dd>{selected.severity}</dd>
              <dt>Observed count</dt><dd>{selected.count}</dd>
              <dt>Evidence</dt><dd>{selected.evidence.join(', ') || '—'}</dd>
              <dt>Request ID</dt><dd>{selected.request_id}</dd>
              <dt>Occurred</dt><dd>{new Date(selected.occurred_at).toLocaleString()}</dd>
            </dl>
            <h3>Triage annotation</h3>
            <div className="field">
              <label htmlFor="triage-status">Status</label>
              <select id="triage-status" value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="new">new</option>
                <option value="acknowledged">acknowledged</option>
                <option value="resolved">resolved</option>
              </select>
            </div>
            <div className="field" style={{ marginTop: 10 }}>
              <label htmlFor="triage-assignee">Assignee</label>
              <input id="triage-assignee" value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="your username" />
            </div>
            <div className="field" style={{ marginTop: 10 }}>
              <label htmlFor="triage-note">Note</label>
              <textarea id="triage-note" value={note} onChange={(event) => setNote(event.target.value)} maxLength={512} />
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button className="btn primary" onClick={saveTriage} disabled={busy}>Save annotation</button>
              <button className="btn" onClick={summarize} disabled={busy}>Add unverified hypothesis</button>
            </div>
            {selected.hypothesis ? (
              <p className="notice readonly" style={{ marginTop: 12 }}>
                <strong>Unverified hypothesis:</strong> {selected.hypothesis}
              </p>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  )
}
