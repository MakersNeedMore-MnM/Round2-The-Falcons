import { useQuery } from "@tanstack/react-query";
import { ExternalLink, PlugZap, ShieldCheck } from "lucide-react";
import { api } from "../api";
import { ErrorState, Loading, PageHeading } from "../components/Ui";

const providers = [
  ["Splunk", "splunk", "SIEM", "Create a signed security-events integration, then configure Splunk HEC or an alert action to POST normalized events to the generated endpoint."],
  ["Microsoft Sentinel", "microsoft_sentinel", "SIEM", "Use a Logic App or Sentinel automation rule to send normalized incidents or alerts through the generated signed webhook."],
  ["Elastic Security", "elastic_security", "SIEM", "Forward normalized detection alerts through an Elastic action connector to the generated signed endpoint."],
  ["CrowdStrike", "crowdstrike", "EDR", "Use Falcon Fusion or a supported outbound workflow to post normalized detection evidence to the signed endpoint."],
  ["Microsoft Defender", "microsoft_defender", "EDR", "Use an approved Microsoft workflow to forward Defender alert evidence to the signed endpoint."],
  ["Generic webhook", "generic_webhook", "SIEM / EDR", "Use any approved producer that can generate the required HMAC signature and normalized payload."],
] as const;

export function ConnectorCatalogPage() {
  const integrations = useQuery({ queryKey: ["integrations"], queryFn: api.integrations });
  if (integrations.isLoading) return <Loading />; if (integrations.error) return <ErrorState error={integrations.error} />;
  return <><PageHeading eyebrow="Phase 33 / vendor connector catalog" title="Live source connectors" copy="Provider-specific onboarding guidance for Cascadia’s signed intake contracts. Connections are created and controlled by an operator; no browser-side credentials are used." />
    <section className="connector-catalog">{providers.map(([name, id, type, guidance]) => { const configured = integrations.data!.filter((item) => item.provider === id); return <article className="data-panel catalog-card" key={id}><header><div><span className="panel-label">{type}</span><h2>{name}</h2></div><PlugZap size={18} /></header><p>{guidance}</p><div><span><ShieldCheck size={14} /> HMAC-signed intake</span><span><b>{configured.length}</b> configured</span></div><a className="text-link" href="/app/launchpad">Create connector <ExternalLink size={13} /></a></article>; })}</section>
    <p className="graph-disclosure">Every connector receives untrusted source content as data only. Validate and normalize payloads server-side; never place webhook secrets, vendor API tokens, or autonomous actions in the browser.</p>
  </>;
}
