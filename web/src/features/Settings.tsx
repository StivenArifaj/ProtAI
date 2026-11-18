import { useState } from 'react'
import { api } from '../api/client'
import { useCheckpoints, useInvalidate, useLimiter, useSettings, useUsers } from '../api/hooks'
import { Badge, Panel, Skeleton, useToast, shortHash, timeLabel } from '../components/ui'

export function Settings() {
  const settings = useSettings()
  const users = useUsers()
  const limiter = useLimiter()
  const checkpoints = useCheckpoints()
  const invalidate = useInvalidate()
  const toast = useToast()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [busy, setBusy] = useState(false)

  const createUser = async () => {
    setBusy(true)
    try {
      const result = await api.createUser({ username, password, role })
      toast(result.message, result.ok)
      setUsername('')
      setPassword('')
      invalidate()
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Create failed', false)
    } finally {
      setBusy(false)
    }
  }

  const seal = async () => {
    setBusy(true)
    try {
      const result = await api.sealCheckpoint()
      toast(result.message, result.ok)
      invalidate()
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Checkpoint failed', false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>Redacted settings, local identities, limiter caveat, and audit checkpoints.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone="warn">post-v1</Badge>
      </div>

      <div className="two-col equal">
        <Panel title="Runtime settings">
          {settings.isLoading ? <Skeleton rows={6} /> : (
            <table className="data">
              <thead><tr><th>Key</th><th>Value</th><th>Restart</th></tr></thead>
              <tbody>
                {settings.data?.map((setting) => (
                  <tr key={setting.key} style={{ cursor: 'default' }}>
                    <td className="mono" style={{ fontSize: 11 }}>{setting.key}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{setting.value}</td>
                    <td>{setting.restart_required ? 'yes' : 'no'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Rate limiter">
          {limiter.data ? (
            <dl className="kv">
              <dt>Store</dt><dd>{limiter.data.store_kind}</dd>
              <dt>Shared</dt><dd>{limiter.data.shared ? 'yes' : 'no'}</dd>
              <dt>Window</dt><dd>{limiter.data.window_seconds}s</dd>
              <dt>Buckets</dt><dd>{limiter.data.buckets.join(', ')}</dd>
            </dl>
          ) : <Skeleton rows={4} />}
          <p className="notice">{limiter.data?.caveat}</p>
        </Panel>
      </div>

      <div className="two-col equal" style={{ marginTop: 16 }}>
        <Panel title="Local console users" actions={<Badge tone="info">SSO adapter ready</Badge>}>
          <table className="data">
            <thead><tr><th>Username</th><th>Role</th><th>Tenant</th></tr></thead>
            <tbody>
              {users.data?.map((user) => (
                <tr key={user.username} style={{ cursor: 'default' }}>
                  <td className="mono" style={{ fontSize: 11 }}>{user.username}</td>
                  <td>{user.role}</td>
                  <td className="faint">{user.tenant_id ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ display: 'flex', gap: 8, marginTop: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <div className="field"><label htmlFor="new-user">Username</label><input id="new-user" value={username} onChange={(event) => setUsername(event.target.value)} /></div>
            <div className="field"><label htmlFor="new-pass">Password (12+ chars)</label><input id="new-pass" type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></div>
            <div className="field">
              <label htmlFor="new-role">Role</label>
              <select id="new-role" value={role} onChange={(event) => setRole(event.target.value)}>
                {['viewer', 'analyst', 'approver', 'operator', 'developer', 'admin'].map((item) => <option key={item}>{item}</option>)}
              </select>
            </div>
            <button className="btn primary" disabled={busy || !username || password.length < 12} onClick={createUser}>Create user</button>
          </div>
        </Panel>

        <Panel title="Audit checkpoints" actions={<button className="btn" disabled={busy} onClick={seal}>Seal current head</button>}>
          {checkpoints.data?.length ? (
            <table className="data">
              <thead><tr><th>#</th><th>Seal</th><th>Head</th><th>Created</th></tr></thead>
              <tbody>
                {checkpoints.data.map((cp) => (
                  <tr key={cp.sequence_number} style={{ cursor: 'default' }}>
                    <td className="mono">{cp.sequence_number}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{shortHash(cp.seal)}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{shortHash(cp.head_hash)}</td>
                    <td className="faint" style={{ fontSize: 11 }}>{timeLabel(cp.occurred_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted" style={{ fontSize: 13 }}>No checkpoints sealed in this process. The local process-local sink is not durable across restarts.</p>}
        </Panel>
      </div>
    </div>
  )
}
