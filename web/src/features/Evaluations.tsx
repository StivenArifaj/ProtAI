import { useReports } from '../api/hooks'
import { Badge, Empty, Panel, Skeleton } from '../components/ui'

export function Evaluations() {
  const reports = useReports()

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Evaluation reports</h1>
          <p>Measurement-only results from the versioned synthetic dataset. Not production accuracy.</p>
        </div>
        <span className="topbar-spacer" />
        <Badge tone="info">6 tasks</Badge>
      </div>

      <div className="notice readonly">
        These metrics are derived by code from synthetic fixtures. They are not risk calibration,
        not benchmark comparability, and never an authorization input.
      </div>

      <Panel title="Reports">
        {reports.isLoading ? <Skeleton rows={6} /> : reports.data?.length ? (
          <table className="data">
            <thead><tr><th>Report</th><th>Generated</th><th>Cases</th><th>Dataset</th></tr></thead>
            <tbody>
              {reports.data.map((report) => (
                <tr key={report.name} style={{ cursor: 'default' }}>
                  <td className="mono" style={{ fontSize: 11 }}>{report.name}</td>
                  <td className="faint" style={{ fontSize: 11 }}>{report.generated_at ?? '—'}</td>
                  <td className="mono">{report.cases ?? '—'}</td>
                  <td className="mono faint" style={{ fontSize: 11 }}>
                    {report.summary.dataset ? JSON.stringify(report.summary.dataset).slice(0, 120) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <Empty title="No reports found" hint="Reports are written by the Phase 9 evaluation CLI to evaluation/reports/." />}
      </Panel>
    </div>
  )
}
