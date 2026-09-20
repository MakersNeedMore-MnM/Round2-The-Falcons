import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleStop, FlaskConical, HeartPulse, Play, Radio } from "lucide-react";
import { useState, type ReactNode } from "react";
import { api } from "../api";
import { Empty, ErrorState, Loading, PageHeading, Severity, time } from "../components/Ui";

export function LabSimulationPage() {
  const client = useQueryClient();
  const assets = useQuery({ queryKey: ["assets"], queryFn: api.assets });
  const scenarios = useQuery({ queryKey: ["lab-scenarios"], queryFn: api.labScenarios });
  const events = useQuery({ queryKey: ["events"], queryFn: api.events, refetchInterval: 1000 });
  const findings = useQuery({ queryKey: ["findings"], queryFn: api.findings, refetchInterval: 1000 });
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.incidents, refetchInterval: 1000 });
  const responses = useQuery({ queryKey: ["responses"], queryFn: api.responses, refetchInterval: 1000 });
  const audits = useQuery({ queryKey: ["audit-events"], queryFn: api.auditEvents, refetchInterval: 1000 });
  const [simulationId, setSimulationId] = useState<string>();
  const [startedStatus, setStartedStatus] = useState<Awaited<ReturnType<typeof api.startLabSimulation>>>();
  const [selectedAsset, setSelectedAsset] = useState("");
  const [selectedScenario, setSelectedScenario] = useState("credential_abuse");
  const simulation = useQuery({ queryKey: ["lab-simulation", simulationId], queryFn: () => api.labSimulation(simulationId!), enabled: Boolean(simulationId), refetchInterval: 800 });
  const start = useMutation({
    mutationFn: api.startLabSimulation,
    onSuccess: (status) => {
      setStartedStatus(status);
      setSimulationId(status.id);
      void Promise.all([
        client.invalidateQueries({ queryKey: ["events"] }),
        client.invalidateQueries({ queryKey: ["findings"] }),
        client.invalidateQueries({ queryKey: ["incidents"] }),
        client.invalidateQueries({ queryKey: ["responses"] }),
        client.invalidateQueries({ queryKey: ["audit-events"] }),
      ]);
    },
  });
  const stop = useMutation({
    mutationFn: api.stopLabSimulation,
    onSuccess: (status) => { setStartedStatus(status); setSimulationId(status.id); },
  });
  const dataQueries = [assets, scenarios, events, findings, incidents, responses, audits];
  if (dataQueries.some((query) => query.isLoading)) return <Loading label="Loading lab controls" />;
  const error = dataQueries.find((query) => query.error)?.error;
  if (error) return <ErrorState error={error} />;
  const assetList = assets.data ?? [];
  const scenarioList = scenarios.data ?? [];
  const eventList = events.data ?? [];
  const findingList = findings.data ?? [];
  const incidentList = incidents.data ?? [];
  const responseList = responses.data ?? [];
  const auditList = audits.data ?? [];
  const labAssets = assetList.filter((asset) => asset.metadata.lab === true || asset.metadata.demo === true);
  const currentAsset = labAssets.find((asset) => asset.id === selectedAsset) ?? labAssets[0];
  const status = simulation.data ?? startedStatus;
  const visibleEvents = eventList.filter((event) => status?.eventIds.includes(event.id));
  const visibleFindings = findingList.filter((finding) => status?.findingIds.includes(finding.id));
  const visibleIncidents = incidentList.filter((incident) => status?.incidentIds.includes(incident.id));
  const responseScenario = status?.responseScenarioId ? responseList.find((scenario) => scenario.id === status.responseScenarioId) : undefined;
  const visibleAudits = auditList.filter((event) => status?.eventIds.includes(event.resourceId) || status?.incidentIds.includes(event.resourceId) || event.eventType.startsWith("response_") || event.eventType === "risk_analysis.created").slice(0, 12);
  const startSimulation = () => {
    if (!currentAsset) return;
    start.mutate({ assetId: currentAsset.id, scenario: selectedScenario });
  };
  return <><PageHeading eyebrow="Controlled lab / synthetic telemetry" title="Live attack detection lab" copy="Run a bounded, synthetic scenario against a selected inventory asset. No commands, remote execution, or response actions are performed." action={status?.status === "running" ? <button className="button button--quiet" onClick={() => stop.mutate(status.id)} disabled={stop.isPending}><CircleStop size={14} /> Stop simulation</button> : undefined} />
    <section className="simulation-boundary"><FlaskConical size={18} /><span>Lab-only evidence · human approval remains required · execution authorized: false</span></section>
    <section className="data-panel lab-controls"><header><div><span className="panel-label">Synthetic scenario</span><h2>Select an asset and bounded sequence</h2></div><Radio size={18} /></header><div className="config-body"><label>Lab asset<select value={selectedAsset || currentAsset?.id || ""} onChange={(event) => setSelectedAsset(event.target.value)}>{labAssets.map((asset) => <option key={asset.id} value={asset.id}>{asset.name} · {asset.criticality}</option>)}</select></label><label>Scenario<select value={selectedScenario} onChange={(event) => setSelectedScenario(event.target.value)}>{scenarioList.map((scenario) => <option key={scenario.id} value={scenario.id}>{scenario.name} · {scenario.eventCount} events</option>)}</select></label><button className="button button--primary" onClick={startSimulation} disabled={!currentAsset || start.isPending || status?.status === "running"}><Play size={14} /> {start.isPending ? "Starting" : "Start lab simulation"}</button>{start.error && <ErrorState error={start.error} />}{!labAssets.length && <p className="blocked-copy">No assets are marked for the lab. Mark an inventory asset with metadata.lab=true before starting.</p>}</div></section>
    {status && <><section className="lab-status-grid"><article><span>Status</span><b>{status.status}</b><small>{status.emittedEvents} events · {status.findingsCreated} findings · {status.incidentsCreated} incidents</small></article><article><span>Safety</span><b className="safe">Synthetic only</b><small>Human approval required</small></article><article><span>Asset heartbeat</span><b><HeartPulse size={14} /> {currentAsset?.name ?? "Selected asset"}</b><small>{time(status.startedAt)}</small></article></section>{status.scenario === "normal_baseline" && status.status === "completed" && <section className="simulation-clear"><HeartPulse size={17} /><div><b>No threat detected</b><span>All three baseline events were processed without creating an anomaly finding or incident.</span></div></section>}{status.projectedRiskAssets?.length ? <section className="data-panel projected-risk"><header><div><span className="panel-label">Consequence intelligence</span><h2>Projected next-risk assets</h2><p>Highest-risk reachable assets from the modeled path. This is decision support, not a guaranteed attack prediction.</p></div></header><div className="projected-risk-list">{status.projectedRiskAssets.map((asset) => <article key={asset.assetId}><div><b>{asset.assetName}</b><small>{asset.riskLevel} risk · path score {asset.riskScore}/100</small><p>{asset.reasons.join(" ")}</p></div><strong>{asset.riskScore}</strong></article>)}</div></section> : null}<section className="lab-chain"><Chain title="1 · Events" count={visibleEvents.length}>{visibleEvents.map((event) => <article key={event.id}><Severity value={event.severity === "informational" ? "low" : event.severity} /><div><b>{event.eventType.replaceAll("_", " ")}</b><small>{event.source} · {time(event.observedAt)}</small></div></article>)}</Chain><Chain title="2 · Findings" count={visibleFindings.length}>{visibleFindings.map((finding) => <article key={finding.id}><Severity value={finding.level} /><div><b>{finding.anomalyScore}/100 anomaly score</b><small>Event {finding.eventId.slice(0, 8)} · {time(finding.createdAt)}</small></div></article>)}</Chain><Chain title="3 · Incident" count={visibleIncidents.length}>{visibleIncidents.map((incident) => <article key={incident.id}><Severity value={incident.severity} /><div><b>{incident.reference} · {incident.title}</b><small>{incident.status} · autonomous actions: false</small></div></article>)}{!visibleIncidents.length && status.status === "completed" && <p className="empty-copy">The correlation threshold was not reached; review findings in Detection and confirm incidents from Incident command.</p>}</Chain><Chain title="4 · Recovery options" count={responseScenario?.options.length ?? 0}>{responseScenario?.options.map((option) => <article key={option.id}><Severity value={option.eligible ? "low" : "high"} /><div><b>{option.title}</b><small>Benefit {option.securityBenefit} · impact {option.operationalImpact} · rollback: {option.rollbackPlan}</small></div></article>) ?? null}{!responseScenario && <p className="empty-copy">Recovery options appear after an incident is correlated.</p>}</Chain><Chain title="5 · Audit trail" count={visibleAudits.length}>{visibleAudits.map((event) => <article key={event.id}><Severity value="low" /><div><b>{event.eventType.replaceAll(".", " / ").replaceAll("_", " ")}</b><small>{event.resourceType} · {event.resourceId.slice(0, 12)} · {time(event.occurredAt)}</small></div></article>)}{!visibleAudits.length && <p className="empty-copy">Audit entries will appear as the simulation progresses.</p>}</Chain></section></>}
    {!status && <Empty title="No simulation running" copy="Select a lab asset and scenario to emit the first synthetic event." />}
  </>;
}

function Chain({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  return <section className="data-panel lab-chain-panel"><header><div><span className="panel-label">{title}</span><h2>{count} signal{count === 1 ? "" : "s"}</h2></div></header><div className="lab-chain-list">{children || <p className="empty-copy">Waiting for the worker.</p>}</div></section>;
}
