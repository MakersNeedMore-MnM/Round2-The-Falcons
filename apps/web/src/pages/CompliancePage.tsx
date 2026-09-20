import { useQuery } from "@tanstack/react-query";
import { FileCheck2 } from "lucide-react";
import { api } from "../api";
import { ErrorState, Loading, PageHeading } from "../components/Ui";

export function CompliancePage() {
  const report = useQuery({ queryKey: ["compliance-readiness"], queryFn: api.complianceReadiness });
  if (report.isLoading) return <Loading label="Reading compliance evidence" />; if (report.error) return <ErrorState error={report.error} />;
  const data = report.data!;
  return <><PageHeading eyebrow="Phase 32 / compliance readiness" title="Control evidence library" copy="Evidence-backed controls from this organization’s stored records. This is decision support—not a certification or legal determination." />
    <section className="data-panel quality-table"><header><div><span className="panel-label">{data.framework.replaceAll("_", " ")}</span><h2>Control readiness</h2></div><FileCheck2 size={18} /></header><div className="table-wrap"><table><thead><tr><th>Control</th><th>Evidence</th><th>Rationale</th><th>Status</th></tr></thead><tbody>{data.controls.map((control) => <tr key={control.id}><td><b>{control.id}</b><small>{control.name}</small></td><td className="mono">{control.evidenceCount}</td><td>{control.rationale}</td><td><span className={`connection connection--${control.status === "satisfied" ? "current" : "stale"}`}>{control.status.replaceAll("_", " ")}</span></td></tr>)}</tbody></table></div></section>
    <section className="data-panel quality-limitations"><header><div><span className="panel-label">Assessment boundary</span><h2>Limitations</h2></div></header><ul>{data.limitations.map((value) => <li key={value}>{value}</li>)}</ul></section>
  </>;
}
