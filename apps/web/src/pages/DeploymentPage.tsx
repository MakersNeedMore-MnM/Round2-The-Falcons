import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, CloudCog } from "lucide-react";
import { api } from "../api";
import { ErrorState, Loading, PageHeading } from "../components/Ui";

export function DeploymentPage() {
  const readiness = useQuery({ queryKey: ["deployment-readiness"], queryFn: api.deploymentReadiness });
  if (readiness.isLoading) return <Loading label="Checking deployment controls" />; if (readiness.error) return <ErrorState error={readiness.error} />;
  const report = readiness.data!;
  return <><PageHeading eyebrow="Phase 23 / release readiness" title="Deployment readiness" copy="A safe configuration checklist for the real production inputs Cascadia cannot generate on your behalf." />
    <section className={`deployment-status deployment-status--${report.readyForProduction ? "ready" : "pending"}`}><CloudCog size={22} /><div><span>Environment: {report.environment}</span><h2>{report.readyForProduction ? "Ready for production release" : "Production action required"}</h2><p>{report.readyForProduction ? "All required production configuration controls are present." : "Complete every required control before directing real traffic to this deployment."}</p></div></section><section className="data-panel deployment-checks"><header><div><span className="panel-label">Configuration controls</span><h2>Release checklist</h2></div></header>{report.checks.map((check) => <article key={check.id}>{check.status === "ready" ? <CheckCircle2 size={17} /> : <CircleAlert size={17} />}<div><b>{check.label}</b><p>{check.detail}</p></div><span className={check.status}>{check.status.replaceAll("_", " ")}</span></article>)}</section>
  </>;
}
