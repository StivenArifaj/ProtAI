import { useState } from 'react'
import { api } from '../api/client'
import { useConnectors, useInvalidate, useTools } from '../api/hooks'
import { Badge, Empty, Panel, Skeleton, useToast } from '../components/ui'

export function Tools() {
  const tools = useTools()
  const connectors = useConnectors()
  const invalidate = useInvalidate()
  const toast = useToast()
  const [reviewId, setReviewId] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState<string | null>(null)

  const mutate = async (id: string, action: 'enable' | 'disable') => {
    setBusy(id)
    try {
      const result = action === 'enable'
        ? await api.enableConnector(id, reviewId[id] ?? '')
        : await api.disableConnector(id)
      toast(result.message, result.ok)
      invalidate()
    } catch (error) {
      toast(error instanceof Error ? error.message : action + ' failed', false)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Tools & connectors</h1>
          <p>Registered capabilities and integration status. No invoke button: the gateway remains the only execution path.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone="info">{tools.data?.length ?? 0} tools</Badge>
      </div>

      <div className="notice readonly">
        Connectors are registered but disabled by default. Enabling one requires a recorded threat-review ID
        and is an explicit operator decision (blueprint §23).
      </div>

      <Panel title="Registered tools">
        {tools.isLoading ? <Skeleton rows={6} /> : tools.data?.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Tool</th><th>Action</th><th>Side effect</th><th>Data class</th><th>In policy</th><th>Destinations</th><th>Timeout</th><th>Concurrency</th></tr></thead>
              <tbody>
                {tools.data.map((tool) => (
                  <tr key={`${tool.tool_id}.${tool.action_id}`} style={{ cursor: 'default' }}>
                    <td className="mono" style={{ fontSize: 11 }}>{tool.tool_id}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{tool.action_id}</td>
                    <td><Badge tone={tool.side_effect_class === 'EXTERNAL_MUTATION' ? 'warn' : 'ok'}>{tool.side_effect_class}</Badge></td>
                    <td>{tool.data_class}</td>
                    <td><Badge tone={tool.enabled_in_policy ? 'ok' : 'neutral'}>{tool.enabled_in_policy ? 'enabled' : 'registered only'}</Badge></td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{tool.external_destinations.join(', ') || '—'}</td>
                    <td className="mono">{tool.timeout_seconds ?? '—'}s</td>
                    <td className="mono">{tool.max_concurrency ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty title="No tools registered" hint="Tool registrations are built at startup from adapters and policy." />}
      </Panel>

      <div style={{ marginTop: 16 }}>
        <Panel title="Company connectors" actions={<Badge tone="warn">disabled by default</Badge>}>
          {connectors.data?.length ? (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Connector</th><th>Status</th><th>Network</th><th>Permissions</th><th>Egress</th><th>Secret ref</th><th>Enabled</th><th>Action</th></tr></thead>
                <tbody>
                  {connectors.data.map((connector) => (
                    <tr key={connector.connector_id} style={{ cursor: 'default' }}>
                      <td><div>{connector.name}</div><div className="mono faint" style={{ fontSize: 11 }}>{connector.connector_id}</div></td>
                      <td><Badge tone={connector.status === 'enabled' ? 'ok' : 'warn'}>{connector.status}</Badge></td>
                      <td>{connector.requires_network ? 'yes' : 'no'}</td>
                      <td className="mono">{connector.permission_count}</td>
                      <td className="mono">{connector.egress_destination_count}</td>
                      <td className="mono faint" style={{ fontSize: 11 }}>{connector.secret_ref_digest ?? '—'}</td>
                      <td className="faint" style={{ fontSize: 11 }}>{connector.enabled_at ? new Date(connector.enabled_at).toLocaleString() : '—'}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <input
                            aria-label={`Threat review ID for ${connector.connector_id}`}
                            value={reviewId[connector.connector_id] ?? ''}
                            onChange={(event) => setReviewId((current) => ({ ...current, [connector.connector_id]: event.target.value }))}
                            placeholder="threat-review id"
                            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 6px', width: 130, fontSize: 11 }}
                          />
                          <button className="btn" disabled={busy === connector.connector_id || !reviewId[connector.connector_id]} onClick={() => mutate(connector.connector_id, 'enable')}>Enable</button>
                          <button className="btn ghost" disabled={busy === connector.connector_id} onClick={() => mutate(connector.connector_id, 'disable')}>Disable</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <Empty title="No connectors registered" hint="The connector framework is a post-v1 foundation; no real connector ships with v1." />}
        </Panel>
      </div>
    </div>
  )
}
