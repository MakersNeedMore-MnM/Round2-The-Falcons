import { useQuery } from "@tanstack/react-query";
import { Activity, Check, Database, RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "../api";
import { ErrorState, Loading, PageHeading, time } from "../components/Ui";

export function SystemPage() {
  const status = useQuery({ queryKey: ["system-status"], queryFn: api.systemStatus, refetchInterval: 30_000 });
  if (status.isLoading) return <Loading label="Checking production controls" />;
  if (status.error) return <ErrorState error={status.error} retry={() => void status.refetch()} />;
  const value = status.data!;
  return <><PageHeading eyebrow="Phase 10 / production operations" title="System health" copy="Live readiness, persistence, and safety controls reported by the running Cascadia service." action={<button className="button button--quiet" onClick={() => void status.refetch()} disabled={status.isFetching}><RefreshCw className={status.isFetching ? "spin" : ""} size={14} /> Refresh</button>} />
    <section className="metric-grid"><article className={`metric-card ${value.status === "degraded" ? "metric-card--red" : ""}`}><div><span>Service state</span><Activity size={16} /></div><strong className="status-word">{value.status}</strong><p>API v{value.version}</p></article><article className={`metric-card ${value.database.status !== "ready" ? "metric-card--red" : ""}`}><div><span>Persistence</span><Database size={16} /></div><strong className="status-word">{value.database.status}</strong><p>{value.database.latencyMs === undefined ? "Database unavailable" : `${value.database.latencyMs} ms readiness query`}</p></article><article className="metric-card"><div><span>Process uptime</span><Activity size={16} /></div><strong>{Math.floor(value.uptimeSeconds / 60)}</strong><p>Minutes since service start</p></article><article className="metric-card"><div><span>Last checked</span><RefreshCw size={16} /></div><strong className="status-word">IST</strong><p>{time(value.checkedAt)}</p></article></section>
    <section className="data-panel system-controls"><header><div><span className="panel-label">Non-negotiable controls</span><h2>Safety invariants</h2></div><ShieldCheck size={18} /></header><div><p><Check size={14} /> Real telemetry only</p><p><Check size={14} /> Human approval required</p><p><Check size={14} /> Autonomous execution disabled</p><p><Check size={14} /> Database readiness verified live</p></div></section>
  </>;
}
