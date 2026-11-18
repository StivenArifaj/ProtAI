import { useConfigs, usePolicy } from '../api/hooks'
import { Badge, Empty, Panel, Skeleton, shortHash } from '../components/ui'

export function Policy() {
  const policy = usePolicy()
  const configs = useConfigs()

  if (policy.isLoading) return <Skeleton rows={10} />
  const data = policy.data

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Policy management</h1>
          <p>Active policy bundle, decision matrix, and validation status. Editing config requires a restart — there is no hot reload.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone="info">v{data?.version ?? '—'}</Badge>
      </div>

      <div className="notice">
        <strong>Restart required.</strong> The running process keeps its startup-loaded bundle.
        Readiness detects file drift and reports 503 until the process is restarted.
      </div>

      <div className="grid-stats">
        <div className="stat">
          <div className="stat-label">Policy version</div>
          <div className="stat-value">{data?.version ?? '—'}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Combined hash</div>
          <div className="stat-value" style={{ fontSize: 13 }}>{shortHash(data?.combined_hash)}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Ask user at risk ≥</div>
          <div className="stat-value">{data?.thresholds.ask_user_at_or_above ?? '—'}</div>
          <div className="stat-note">experimental threshold</div>
        </div>
        <div className="stat">
          <div className="stat-label">Block at risk ≥</div>
          <div className="stat-value">{data?.thresholds.block_at_or_above ?? '—'}</div>
          <div className="stat-note">experimental threshold</div>
        </div>
      </div>

      <Panel title="Decision matrix (active bundle)">
        {data?.tools.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Tool</th><th>Action</th><th>Side effect</th><th>Data class</th><th>Enabled</th><th>Egress destinations</th></tr></thead>
              <tbody>
                {data.tools.map((tool) => (
                  <tr key={`${tool.tool_id}.${tool.action_id}`} style={{ cursor: 'default' }}>
                    <td className="mono" style={{ fontSize: 11 }}>{tool.tool_id}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{tool.action_id}</td>
                    <td>{tool.side_effect_class}</td>
                    <td>{tool.data_class}</td>
                    <td><Badge tone={tool.enabled_in_policy ? 'ok' : 'neutral'}>{tool.enabled_in_policy ? 'allowed' : 'disabled'}</Badge></td>
                    <td className="mono faint" style={{ fontSize: 11 }}>{tool.external_destinations.join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty title="No policy tools" hint="Policy documents are validated at startup." />}
      </Panel>

      <div className="two-col equal" style={{ marginTop: 16 }}>
        <Panel title="Self-check fixtures">
          {data?.self_checks.length ? (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {data.self_checks.map((name) => <li key={name} className="mono" style={{ fontSize: 12 }}>{name}</li>)}
            </ul>
          ) : <p className="muted" style={{ fontSize: 13 }}>Fixture names are wired at startup; this deployment exposes none.</p>}
        </Panel>
        <Panel title="Security configuration">
          {configs.data?.length ? (
            <div style={{ display: 'grid', gap: 8 }}>
              {configs.data.map((config) => (
                <div key={config.name} style={{ display: 'flex', gap: 10, alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 6 }}>
                  <span className="mono" style={{ fontSize: 12 }}>{config.name}</span>
                  <Badge tone="info">v{config.version}</Badge>
                  <span className="faint" style={{ fontSize: 11 }}>
                    {Object.entries(config.summary).map(([key, value]) => `${key}=${value}`).join(' · ')}
                  </span>
                </div>
              ))}
            </div>
          ) : <p className="muted" style={{ fontSize: 13 }}>No config projections available.</p>}
        </Panel>
      </div>
    </div>
  )
}
