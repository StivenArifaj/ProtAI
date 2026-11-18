import { useState } from 'react'
import { api } from '../api/client'
import { useApprovals, useInvalidate } from '../api/hooks'
import type { Approval } from '../api/types'
import { Badge, Drawer, Empty, Skeleton, useToast, timeLabel } from '../components/ui'

function tone(status: string): 'ok' | 'bad' | 'warn' | 'info' {
  if (status === 'approved' || status === 'consumed') return 'ok'
  if (status === 'denied' || status === 'revoked' || status === 'expired') return 'bad'
  if (status === 'pending') return 'warn'
  return 'info'
}

export function Approvals() {
  const approvals = useApprovals()
  const invalidate = useInvalidate()
  const toast = useToast()
  const [selected, setSelected] = useState<Approval | null>(null)
  const [token, setToken] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)

  const decide = async (approve: boolean) => {
    if (!selected || !token) return
    setBusy(true)
    try {
      const result = await api.decide(selected.approval_id, token, approve)
      toast(result.message, result.ok)
      setToken('')
      invalidate()
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Decision failed', false)
    } finally {
      setBusy(false)
    }
  }

  const revoke = async () => {
    if (!selected || !reason) return
    setBusy(true)
    try {
      const result = await api.revoke(selected.approval_id, reason)
      toast(result.message, result.ok)
      setReason('')
      invalidate()
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Revocation failed', false)
    } finally {
      setBusy(false)
    }
  }

  const pending = (approvals.data ?? []).filter((item) => item.status === 'pending')

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Approval requests</h1>
          <p>Human decisions on sensitive operations. Each decision is one-time and audited.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone="warn">{pending.length} pending</Badge>
      </div>

      <div className="notice">
        <strong>Token handling:</strong> the one-time approval token is pasted here only when deciding.
        The console never stores it in browser storage, URLs, or logs. Expiry is enforced lazily.
      </div>

      <div className="panel">
        <div className="panel-head"><span className="panel-title">Approval queue</span></div>
        {approvals.isLoading ? <Skeleton rows={8} /> : approvals.data?.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>Approval</th><th>Requested</th><th>Expires</th><th>Tool / action</th><th>Requester</th><th>Risk</th><th>Status</th><th>Rule</th></tr>
              </thead>
              <tbody>
                {approvals.data.map((item) => (
                  <tr key={item.approval_id} onClick={() => setSelected(item)}>
                    <td className="mono" style={{ fontSize: 11 }}>{item.approval_id.slice(0, 10)}…</td>
                    <td className="faint" style={{ fontSize: 11 }}>{timeLabel(item.created_at)}</td>
                    <td className="faint" style={{ fontSize: 11 }}>{timeLabel(item.expires_at)}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{item.tool_id}.{item.action_id}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{item.requester_subject_id}</td>
                    <td className="mono">{item.risk_score}</td>
                    <td><Badge tone={tone(item.status)}>{item.status}</Badge></td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{item.required_approver_rule}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="No approval requests"
            hint="The starter policy enables no approval-eligible tool; approvals appear here when a policy asks for them."
          />
        )}
      </div>

      <Drawer
        open={selected !== null}
        onOpenChange={(open) => !open && setSelected(null)}
        title="Approval decision"
        subtitle={selected ? selected.approval_id : undefined}
      >
        {selected ? (
          <div>
            <h3>Bound action facts</h3>
            <dl className="kv">
              <dt>Request ID</dt><dd>{selected.request_id}</dd>
              <dt>Tool / action</dt><dd>{selected.tool_id}.{selected.action_id}</dd>
              <dt>Requester</dt><dd>{selected.requester_subject_id}</dd>
              <dt>Tenant</dt><dd>{selected.tenant_id ?? '—'}</dd>
              <dt>Resources</dt><dd>{selected.resource_count}</dd>
              <dt>Destination</dt><dd>{selected.destination ?? '—'}</dd>
              <dt>Risk</dt><dd>{selected.risk_score}</dd>
              <dt>Policy</dt><dd>{selected.policy_version} · {selected.policy_hash.slice(0, 12)}…</dd>
              <dt>Status</dt><dd>{selected.status}</dd>
              <dt>Expires</dt><dd>{timeLabel(selected.expires_at)}</dd>
              <dt>Decided by</dt><dd>{selected.decided_by_subject_id ?? '—'}</dd>
              <dt>Self-approval</dt><dd>{selected.self_approval_allowed ? 'allowed' : 'forbidden'}</dd>
            </dl>

            {selected.status === 'pending' ? (
              <>
                <h3>One-time decision</h3>
                <div className="field">
                  <label htmlFor="approval-token">Approval token (not stored)</label>
                  <input
                    id="approval-token"
                    type="password"
                    value={token}
                    onChange={(event) => setToken(event.target.value)}
                    autoComplete="off"
                    placeholder="paste the token delivered out-of-band"
                  />
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                  <button className="btn primary" disabled={busy || !token} onClick={() => decide(true)}>Approve</button>
                  <button className="btn danger" disabled={busy || !token} onClick={() => decide(false)}>Deny</button>
                </div>
              </>
            ) : (
              <p className="notice readonly">This approval is {selected.status} and can no longer be decided.</p>
            )}

            {selected.status === 'approved' ? (
              <>
                <h3 style={{ marginTop: 18 }}>Revoke before consumption</h3>
                <div className="field">
                  <label htmlFor="revoke-reason">Reason</label>
                  <input id="revoke-reason" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={256} />
                </div>
                <button className="btn danger" style={{ marginTop: 10 }} disabled={busy || !reason} onClick={revoke}>
                  Revoke approval
                </button>
              </>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  )
}
