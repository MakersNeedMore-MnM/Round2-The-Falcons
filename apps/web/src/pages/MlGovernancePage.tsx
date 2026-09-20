import { useQuery } from "@tanstack/react-query";
import { BrainCircuit, ShieldCheck, UserRoundCheck } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorState, Loading, PageHeading, time } from "../components/Ui";

export function MlGovernancePage() {
  const report = useQuery({ queryKey: ["ml-governance"], queryFn: api.mlGovernance });
  if (report.isLoading) return <Loading label="Reading model governance evidence" />; if (report.error) return <ErrorState error={report.error} />;
  const data = report.data!;
  return <><PageHeading eyebrow="Phase 31 / ML governance" title="Model oversight register" copy="Training provenance, model status, and analyst review outcomes for stored detection models. These measures support governance; they are not performance claims." />
    <section className="topology-facts quality-facts"><span><BrainCircuit size={16} /><b>{data.models.length}</b> model versions</span><span><ShieldCheck size={16} /><b>{data.models.filter((model) => model.status === "active").length}</b> active model</span><span><UserRoundCheck size={16} /><b>{data.models.reduce((total, model) => total + model.findingsReviewed, 0)}</b> reviewed findings</span><span><BrainCircuit size={16} /><b>0</b> autonomous actions</span></section>
    <section className="governance-models">{data.models.map((model) => <article className="data-panel governance-model" key={model.id}><header><div><span className="panel-label">Model v{model.version} · {model.status}</span><h2>{model.algorithm.replaceAll("_", " ")}</h2></div><span className={`connection connection--${model.status}`}>{model.status}</span></header><div className="governance-grid"><span><small>Training data</small><b>{model.trainingEventCount}</b><em>stored events</em></span><span><small>Trained</small><b>{time(model.trainedAt)}</b><em>IST evidence</em></span><span><small>Threshold</small><b>{model.findingThreshold}/100</b><em>review trigger</em></span><span><small>Reviewed</small><b>{model.findingsReviewed}/{model.findingsCreated}</b><em>finding workflow</em></span></div><div className="disposition-summary"><span>New <b>{model.dispositions.new}</b></span><span>Acknowledged <b>{model.dispositions.acknowledged}</b></span><span>Dismissed <b>{model.dispositions.dismissed}</b></span><span>Escalated <b>{model.dispositions.escalated}</b></span></div><p className="governance-boundary">Human review: required · Autonomous response: disabled</p></article>)}{!data.models.length && <Empty title="No detection models" copy="Train a model from sufficient stored security events to create durable governance evidence." />}</section>
    <section className="data-panel quality-limitations"><header><div><span className="panel-label">Measurement boundary</span><h2>Interpretation limits</h2></div></header><ul>{data.limitations.map((item) => <li key={item}>{item}</li>)}</ul></section>
  </>;
}
