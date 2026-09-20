import { useQuery } from "@tanstack/react-query";
import { FileText, ShieldAlert, Target } from "lucide-react";
import { api } from "../api";
import { ErrorState, Loading, PageHeading, Severity, time } from "../components/Ui";

export function ExecutiveBriefPage() {
  const report = useQuery({ queryKey: ["executive-report"], queryFn: api.executiveReport });
  if (report.isLoading) return <Loading label="Preparing governed executive brief" />; if (report.error) return <ErrorState error={report.error} />;
  const data = report.data!;
  return <><PageHeading eyebrow="Phase 37 / executive analytics" title="Leadership resilience brief" copy="A confidential, integrity-checked summary generated only from stored Cascadia evidence. It is decision support—not a compliance certification or response authorization." />
    <section className="assurance-hero"><div><span>Posture score</span><strong>{data.posture.score}</strong><b>Grade {data.posture.grade}</b></div><dl><div><dt>Priority items</dt><dd>{data.posture.priorities.length}</dd></div><div><dt>Open high incidents</dt><dd>{data.posture.exposure.openHighIncidents}</dd></div><div><dt>Active sources</dt><dd>{data.posture.coverage.activeIntegrations}</dd></div><div><dt>Audit evidence</dt><dd>{data.governance.evidence.auditEvents}</dd></div></dl></section>
    <section className="data-panel"><header><div><span className="panel-label">Leadership attention</span><h2>Current priorities</h2></div><Target size={18} /></header><div className="priority-list">{data.posture.priorities.map((item) => <article key={item.id}><Severity value={item.severity} /><div><b>{item.title}</b><p>{item.rationale}</p></div></article>)}{!data.posture.priorities.length && <p className="empty-copy">No urgent priorities are derived from current stored evidence.</p>}</div></section>
    <section className="data-panel executive-integrity"><header><div><span className="panel-label">Report integrity</span><h2>Governed artifact</h2></div><FileText size={18} /></header><p><ShieldAlert size={15} /> Confidential report generated {time(data.generatedAt)}.</p><code>{data.integritySha256}</code></section>
  </>;
}
