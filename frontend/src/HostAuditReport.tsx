import { rows, date } from "./api";
import type { Json } from "./api";

export function HostAuditReport({ report }: { report: Json }) {
  return <section aria-label="Read-only audit report">
    <h3>Read-only host audit</h3>
    <p>{report.summary}</p>
    <p className="muted">Received {date(report.received_at)} · {report.total_findings || 0} findings · No changes executed</p>
    <p>Historical baseline: {report.baseline_comparison?.status || "not supplied"}. Historical measurements are unverified.</p>
    <p>WAN exposure: {report.exposure?.wan_exposure || "unverified"}. Listener configuration does not prove internet exposure.</p>
    {report.coverage_gaps?.length > 0 && <details><summary>Missing evidence ({report.coverage_gaps.length})</summary><ul>{report.coverage_gaps.map((gap: string) => <li key={gap}>{gap.replaceAll("_", " ")}</li>)}</ul></details>}
    {rows(report.findings).map((finding) => <details key={finding.id} className="panel">
      <summary>{finding.priority}. {finding.title} · {finding.severity}</summary>
      <p className="mono">{finding.target} · {finding.confidence}</p>
      <p>{finding.impact}</p>
      <h4>Plan for owner review</h4>
      <ol>{(finding.action_plan?.steps || []).map((step: string, index: number) => <li key={index}>{step}</li>)}</ol>
      <p>Risk: {finding.action_plan?.risk}. Separate approval is required before any change.</p>
      <h4>Verification before continuing</h4>
      <ul>{(finding.action_plan?.verification || []).map((step: string, index: number) => <li key={index}>{step}</li>)}</ul>
      <p>{finding.action_plan?.rollback}</p>
      <details><summary>Measured/configuration evidence</summary><pre className="json-view">{JSON.stringify(finding.evidence, null, 2)}</pre></details>
    </details>)}
    {report.truncated && <p className="muted">Showing the first 100 prioritized findings.</p>}
    <details><summary>Proposed zones and declared dependencies</summary><p>Zone names are inferred. Runtime communication and multicast requirements must be verified before a staged migration.</p><pre className="json-view">{JSON.stringify({ zones: report.zone_proposal, dependencies: report.dependency_declarations }, null, 2)}</pre></details>
  </section>;
}
