import { useQuery } from "@tanstack/react-query";
import { CircleDot, Network, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorState, Loading, PageHeading } from "../components/Ui";

type GraphNode = { id: string; label: string; kind: "asset" | "event" | "finding" | "indicator" | "incident" };
type GraphEdge = { id: string; from: string; to: string; label: string };
const placement = (index: number, total: number) => ({ x: 80 + ((index * 149) % 820), y: 72 + (Math.floor(index / 6) * 115) % Math.max(120, Math.ceil(total / 6) * 115) });

export function ThreatGraphPage() {
  const assets = useQuery({ queryKey: ["assets"], queryFn: api.assets }); const events = useQuery({ queryKey: ["events"], queryFn: api.events }); const findings = useQuery({ queryKey: ["findings"], queryFn: api.findings }); const indicators = useQuery({ queryKey: ["indicators"], queryFn: api.indicators }); const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.incidents });
  if ([assets, events, findings, indicators, incidents].some((query) => query.isLoading)) return <Loading label="Reading linked operational evidence" />;
  const error = assets.error ?? events.error ?? findings.error ?? indicators.error ?? incidents.error; if (error) return <ErrorState error={error} />;
  const nodes: GraphNode[] = []; const edges: GraphEdge[] = []; const assetIds = new Map(assets.data!.map((asset) => [asset.externalId, asset.id]));
  assets.data!.forEach((asset) => nodes.push({ id: asset.id, label: asset.name, kind: "asset" }));
  events.data!.forEach((event) => { const eventNode = `event:${event.id}`; nodes.push({ id: eventNode, label: event.eventType, kind: "event" }); event.assetExternalIds.forEach((externalId) => { const assetId = assetIds.get(externalId); if (assetId) edges.push({ id: `${eventNode}:${assetId}`, from: eventNode, to: assetId, label: "observed on" }); }); });
  findings.data!.forEach((finding) => { const findingNode = `finding:${finding.id}`; const eventNode = `event:${finding.eventId}`; nodes.push({ id: findingNode, label: `${finding.level} anomaly`, kind: "finding" }); if (nodes.some((node) => node.id === eventNode)) edges.push({ id: `${findingNode}:${eventNode}`, from: findingNode, to: eventNode, label: "derived from" }); });
  indicators.data!.forEach((indicator) => nodes.push({ id: `indicator:${indicator.id}`, label: indicator.name || indicator.stixId, kind: "indicator" }));
  incidents.data!.forEach((incident) => { const incidentNode = `incident:${incident.id}`; nodes.push({ id: incidentNode, label: incident.title, kind: "incident" }); incident.evidence.forEach((evidence) => { const target = evidence.kind === "security_event" ? `event:${evidence.resourceId}` : evidence.kind === "anomaly_finding" ? `finding:${evidence.resourceId}` : evidence.kind === "threat_indicator" ? `indicator:${evidence.resourceId}` : undefined; if (target && nodes.some((node) => node.id === target)) edges.push({ id: `${incidentNode}:${evidence.id}`, from: incidentNode, to: target, label: "evidence" }); }); });
  const points = new Map(nodes.map((node, index) => [node.id, placement(index, nodes.length)])); const graphHeight = Math.max(310, Math.ceil(nodes.length / 6) * 115 + 70);
  return <><PageHeading eyebrow="Phase 29 / threat knowledge graph" title="Evidence relationship graph" copy="Relationships are drawn only from stored event-to-asset mappings, finding provenance, and manually linked incident evidence. Unlinked threat indicators remain unlinked." />
    <section className="topology-facts graph-facts"><span><Network size={16} /><b>{nodes.length}</b> evidence nodes</span><span><CircleDot size={16} /><b>{edges.length}</b> stored edges</span><span><Sparkles size={16} /><b>{indicators.data!.length}</b> threat indicators</span><span><ShieldAlert size={16} /><b>{incidents.data!.length}</b> incidents</span></section>
    <section className="data-panel knowledge-graph"><header><div><span className="panel-label">Evidence-only graph</span><h2>Threat and operational context</h2></div><Network size={18} /></header>{nodes.length ? <div className="graph-canvas" style={{ height: graphHeight }}><svg viewBox={`0 0 1000 ${graphHeight}`} preserveAspectRatio="none" aria-hidden="true">{edges.map((edge) => { const from = points.get(edge.from)!; const to = points.get(edge.to)!; return <line key={edge.id} x1={from.x} y1={from.y} x2={to.x} y2={to.y} />; })}</svg>{nodes.map((node) => { const point = points.get(node.id)!; return <span key={node.id} className={`graph-node graph-node--${node.kind}`} style={{ left: `${point.x / 10}%`, top: point.y }} title={`${node.kind}: ${node.label}`}><i />{node.label}</span>; })}</div> : <Empty title="No graph evidence yet" copy="Ingest real events, link them to stored asset external IDs, or add incident evidence to reveal durable relationships." />}</section>
    <p className="graph-disclosure">Threat indicators are source intelligence, not proof of impact. Add evidence through incident workflows before they become connected to an incident.</p>
  </>;
}
