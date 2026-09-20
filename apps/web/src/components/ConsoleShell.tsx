import { Activity, BellRing, Boxes, BrainCircuit, CheckSquare, ChevronRight, ClipboardList, CloudCog, FileBadge, FileCheck2, FileText, FileUp, FlaskConical, GitBranch, HeartPulse, History, LogOut, MapPinned, Network, PlugZap, RadioTower, Rocket, Settings, Settings2, ShieldAlert, TerminalSquare, Users, Vote } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { api, ApiError, session } from "../api";
import { AssetsPage, DetectionPage, IncidentsPage, IntegrationsPage, OverviewPage, ResponsesPage, RiskPage } from "../pages/ConsolePages";
import { Brand } from "./Brand";
import { ResilienceScene } from "./ResilienceScene";
import { ErrorState, Loading } from "./Ui";
import { IdentityPage } from "../pages/IdentityPage";
import { SystemPage } from "../pages/SystemPage";
import { AssurancePage } from "../pages/AssurancePage";
import { LaunchpadPage } from "../pages/LaunchpadPage";
import { EvidencePage } from "../pages/EvidencePage";
import { ConnectorOpsPage } from "../pages/ConnectorOpsPage";
import { WorkQueuePage } from "../pages/WorkQueuePage";
import { TaskboardPage } from "../pages/TaskboardPage";
import { ImportPage } from "../pages/ImportPage";
import { DecisionDeskPage } from "../pages/DecisionDeskPage";
import { ConfigurationPage } from "../pages/ConfigurationPage";
import { SimulationPage } from "../pages/SimulationPage";
import { DeploymentPage } from "../pages/DeploymentPage";
import { TopologyPage } from "../pages/TopologyPage";
import { EnrichmentPage } from "../pages/EnrichmentPage";
import { NotificationsPage } from "../pages/NotificationsPage";
import { ThreatGraphPage } from "../pages/ThreatGraphPage";
import { DataQualityPage } from "../pages/DataQualityPage";
import { MlGovernancePage } from "../pages/MlGovernancePage";
import { CompliancePage } from "../pages/CompliancePage";
import { ConnectorCatalogPage } from "../pages/ConnectorCatalogPage";
import { ResilienceReadinessPage } from "../pages/ResilienceReadinessPage";
import { ExecutiveBriefPage } from "../pages/ExecutiveBriefPage";
import { LabSimulationPage } from "../pages/LabSimulationPage";

const navigation = [
  { to: "/app/lab", label: "Live detection lab", icon: RadioTower, permission: "operations" },
  { to: "/app", label: "Overview", icon: Activity, end: true, permission: "read" },
  { to: "/app/detection", label: "Detection", icon: BrainCircuit, permission: "operations" },
  { to: "/app/incidents", label: "Incidents", icon: ShieldAlert, permission: "incidents" },
  { to: "/app/responses", label: "Responses", icon: Network, permission: "responses" },
  { to: "/app/decisions", label: "Decision desk", icon: Vote, permission: "responses" },
  { to: "/app/evidence", label: "Evidence", icon: History, permission: "read" },
  { to: "/app/risk", label: "Attack paths", icon: GitBranch, permission: "assets" },
  { to: "/app/assets", label: "Assets", icon: Boxes, permission: "assets" },
  { to: "/app/topology", label: "Operational map", icon: MapPinned, permission: "assets" },
  { to: "/app/threat-graph", label: "Threat graph", icon: Network, permission: "operations" },
  { to: "/app/taskboard", label: "Taskboard", icon: CheckSquare, permission: "tasks" },
  { to: "/app/work-queue", label: "Work queue", icon: ClipboardList, permission: "operations" },
  { to: "/app/simulate", label: "Simulate response", icon: FlaskConical, permission: "simulate" },
  { to: "/app/enrichment", label: "Asset intelligence", icon: FileBadge, permission: "assets" },
  { to: "/app/data-quality", label: "Data quality", icon: Activity, permission: "read" },
  { to: "/app/integrations", label: "Integrations", icon: RadioTower, permission: "read" },
  { to: "/app/import", label: "Import inventory", icon: FileUp, permission: "assets" },
  { to: "/app/configuration", label: "Configuration", icon: Settings, permission: "all" },
  { to: "/app/identity", label: "Identity", icon: Users, permission: "all" },
  { to: "/app/ml-governance", label: "ML governance", icon: BrainCircuit, permission: "operations" },
  { to: "/app/resilience", label: "Resilience readiness", icon: FlaskConical, permission: "read" },
  { to: "/app/assurance", label: "Assurance", icon: FileCheck2, permission: "assurance" },
  { to: "/app/system", label: "System", icon: HeartPulse, permission: "read" },
  { to: "/app/deployment", label: "Deployment", icon: CloudCog, permission: "all" },
  { to: "/app/compliance", label: "Compliance", icon: FileCheck2, permission: "assurance" },
  { to: "/app/executive-brief", label: "Executive brief", icon: FileText, permission: "assurance" },
  { to: "/app/notifications", label: "Notifications", icon: BellRing, permission: "notifications" },
  { to: "/app/connectors", label: "Connector ops", icon: Settings2, permission: "all" },
  { to: "/app/connector-catalog", label: "Connector catalog", icon: PlugZap, permission: "read" },
  { to: "/app/launchpad", label: "Launchpad", icon: Rocket, permission: "all" },
];

export function ConsoleShell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const localToken = Boolean(session.get());
  const browserSession = useQuery({ queryKey: ["auth-session"], queryFn: api.authSession, enabled: !localToken, retry: false });
  const localOrganization = useQuery({ queryKey: ["organization"], queryFn: api.organization, enabled: localToken });
  const access = useQuery({ queryKey: ["access-context"], queryFn: api.accessContext, retry: false });
  useEffect(() => {
    const liveQueryKeys = ["events", "findings", "incidents", "responses", "audit-events", "audit-anchors", "analyses", "models"];
    const refresh = () => {
      for (const queryKey of liveQueryKeys) void queryClient.invalidateQueries({ queryKey: [queryKey] });
    };
    const timer = window.setInterval(refresh, 1500);
    return () => window.clearInterval(timer);
  }, [queryClient]);
  const organization = localToken ? localOrganization.data : browserSession.data?.organization;
  const authError = localToken ? localOrganization.error : browserSession.error;
  const loading = localToken ? localOrganization.isLoading : browserSession.isLoading;
  if (loading) return <main className="console-gate"><ResilienceScene mode="console" /><Loading label="Authenticating the operations plane" /></main>;
  if (authError) return <main className="console-gate"><ResilienceScene mode="console" /><div className="gate-error"><ErrorState error={authError} retry={() => localToken ? localOrganization.refetch() : browserSession.refetch()} />{authError instanceof ApiError && authError.status === 401 && <button className="button button--primary" onClick={() => { session.clear(); navigate("/connect"); }}>Sign in</button>}</div></main>;
  if (!organization) return <Navigate to="/connect" replace />;
  const disconnect = async () => {
    if (localToken) session.clear(); else await api.logout();
    queryClient.clear();
    navigate("/");
  };
  // Presentation fallback only: never hide navigation because an API restart delayed the access-context response.
  // Every operation remains independently authorized by the API.
  const permissions = access.data?.permissions ?? ["all"];
  const visibleNavigation = navigation.filter((item) => permissions.includes("all") || permissions.includes(item.permission));
  return <div className="console"><ResilienceScene mode="console" /><aside className="sidebar"><Brand /><nav aria-label="Operations navigation">{visibleNavigation.map(({ to, label, icon: Icon, end }) => <NavLink end={end} key={to} to={to}><Icon size={16} /><span>{label}</span><ChevronRight className="nav-arrow" size={13} /></NavLink>)}</nav><div className="sidebar-foot"><span><i /> {localToken ? "Local API connected" : "MFA session active"}</span><button onClick={() => void disconnect()}><LogOut size={14} /> Sign out</button></div></aside>
    <div className="console-main"><header className="console-topbar"><div><span className="eyebrow">Active organization</span><b>{organization.name}</b></div><div className="topbar-status"><TerminalSquare size={14} /><span>{browserSession.data ? `${browserSession.data.role.replaceAll("_", " ")} / MFA` : "Human-governed"}</span></div></header><main className="console-content"><Routes><Route index element={<OverviewPage />} /><Route path="launchpad" element={<LaunchpadPage />} /><Route path="assets" element={<AssetsPage />} /><Route path="import" element={<ImportPage />} /><Route path="configuration" element={<ConfigurationPage />} /><Route path="enrichment" element={<EnrichmentPage />} /><Route path="threat-graph" element={<ThreatGraphPage />} /><Route path="data-quality" element={<DataQualityPage />} /><Route path="ml-governance" element={<MlGovernancePage />} /><Route path="compliance" element={<CompliancePage />} /><Route path="connector-catalog" element={<ConnectorCatalogPage />} /><Route path="resilience" element={<ResilienceReadinessPage />} /><Route path="executive-brief" element={<ExecutiveBriefPage />} /><Route path="notifications" element={<NotificationsPage />} /><Route path="detection" element={<DetectionPage />} /><Route path="risk" element={<RiskPage />} /><Route path="topology" element={<TopologyPage />} /><Route path="work-queue" element={<WorkQueuePage />} /><Route path="incidents" element={<IncidentsPage />} /><Route path="responses" element={<ResponsesPage />} /><Route path="decisions" element={<DecisionDeskPage />} /><Route path="simulate" element={<SimulationPage />} /><Route path="lab" element={<LabSimulationPage />} /><Route path="taskboard" element={<TaskboardPage />} /><Route path="integrations" element={<IntegrationsPage />} /><Route path="connectors" element={<ConnectorOpsPage />} /><Route path="identity" element={<IdentityPage />} /><Route path="assurance" element={<AssurancePage />} /><Route path="evidence" element={<EvidencePage />} /><Route path="system" element={<SystemPage />} /><Route path="deployment" element={<DeploymentPage />} /><Route path="*" element={<Navigate to="/app" replace />} /></Routes></main></div>
  </div>;
}
