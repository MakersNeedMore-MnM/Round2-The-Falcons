import { useQuery } from "@tanstack/react-query";
import { ArrowRight, ClipboardList, Filter } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { ErrorState, Loading, PageHeading, Severity, time } from "../components/Ui";

type QueueItem = { id: string; title: string; rationale: string; severity: "low" | "medium" | "high" | "critical"; kind: "incident" | "finding" | "vulnerability"; createdAt: string; to: string };
const rank = { critical: 0, high: 1, medium: 2, low: 3 };

export function WorkQueuePage() {
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.incidents }); const findings = useQuery({ queryKey: ["findings"], queryFn: api.findings }); const vulnerabilities = useQuery({ queryKey: ["vulnerabilities"], queryFn: api.vulnerabilities }); const [filter, setFilter] = useState<"all" | QueueItem["kind"]>("all");
  const error = [incidents, findings, vulnerabilities].find((query) => query.error)?.error; if (incidents.isLoading || findings.isLoading || vulnerabilities.isLoading) return <Loading label="Building the analyst work queue" />; if (error) return <ErrorState error={error} />;
  const items = useMemo<QueueItem[]>(() => [
    ...incidents.data!.filter((item) => !["resolved", "closed"].includes(item.status)).map((item) => ({ id: item.id, title: item.title, rationale: `${item.reference} is ${item.status}; acknowledge by ${time(item.acknowledgementDueAt)}.`, severity: item.severity, kind: "incident" as const, createdAt: item.createdAt, to: "/app/incidents" })),
    ...findings.data!.filter((item) => item.disposition === "new" || item.disposition === "escalated").map((item) => ({ id: item.id, title: `Review ${item.level} anomaly finding`, rationale: `Explainable score ${item.anomalyScore}/100 is ${item.disposition}.`, severity: item.level, kind: "finding" as const, createdAt: item.createdAt, to: "/app/detection" })),
    ...vulnerabilities.data!.filter((item) => item.status === "open" && item.exploitStatus !== "none_known").map((item) => ({ id: item.id, title: item.title, rationale: `${item.exploitStatus.replaceAll("_", " ")} · CVSS ${item.cvssScore} · ${item.externalId}.`, severity: item.exploitStatus === "active_exploitation" ? "critical" as const : item.cvssScore >= 7 ? "high" as const : "medium" as const, kind: "vulnerability" as const, createdAt: item.updatedAt, to: "/app/assets" })),
  ].sort((a, b) => rank[a.severity] - rank[b.severity] || b.createdAt.localeCompare(a.createdAt)), [incidents.data, findings.data, vulnerabilities.data]);
  const visible = filter === "all" ? items : items.filter((item) => item.kind === filter);
  return <><PageHeading eyebrow="Phase 17 / analyst work queue" title="Work queue" copy="Prioritized real work from the stored evidence plane. Analysts retain responsibility for every decision and lifecycle change." />
    <section className="queue-summary"><span><b>{items.length}</b> open work items</span><span><b>{items.filter((item) => item.severity === "critical").length}</b> critical</span><span><b>{items.filter((item) => item.kind === "incident").length}</b> incidents</span><span><b>{items.filter((item) => item.kind === "finding").length}</b> findings</span></section>
    <section className="data-panel work-queue"><header><div><span className="panel-label">Human worklist</span><h2>Evidence requiring attention</h2></div><label><Filter size={14} /><select value={filter} onChange={(event) => setFilter(event.target.value as typeof filter)}><option value="all">All work</option><option value="incident">Incidents</option><option value="finding">Findings</option><option value="vulnerability">Vulnerabilities</option></select></label></header>{visible.map((item) => <article key={`${item.kind}-${item.id}`}><Severity value={item.severity} /><div><span>{item.kind}</span><b>{item.title}</b><p>{item.rationale}</p></div><Link to={item.to}>Open workspace <ArrowRight size={14} /></Link></article>)}{!visible.length && <div className="empty"><ClipboardList size={24} /><h3>No matching work</h3><p>No stored evidence currently matches this queue filter.</p></div>}</section>
  </>;
}
