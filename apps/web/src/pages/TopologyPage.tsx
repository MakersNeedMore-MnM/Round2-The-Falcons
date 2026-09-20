import { useQuery } from "@tanstack/react-query";
import { MapPinned, Network, Route, Satellite } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorState, Loading, PageHeading, Severity } from "../components/Ui";

type LocatedAsset = { id: string; name: string; criticality: "low" | "medium" | "high" | "critical"; latitude: number; longitude: number; siteName?: string };
function locationOf(asset: Awaited<ReturnType<typeof api.assets>>[number]): LocatedAsset | undefined {
  const latitude = asset.metadata.latitude; const longitude = asset.metadata.longitude;
  if (typeof latitude !== "number" || typeof longitude !== "number" || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) return undefined;
  return { id: asset.id, name: asset.name, criticality: asset.criticality, latitude, longitude, ...(typeof asset.metadata.siteName === "string" ? { siteName: asset.metadata.siteName } : {}) };
}

export function TopologyPage() {
  const assets = useQuery({ queryKey: ["assets"], queryFn: api.assets }); const dependencies = useQuery({ queryKey: ["dependencies"], queryFn: api.dependencies }); const services = useQuery({ queryKey: ["services"], queryFn: api.services });
  if (assets.isLoading || dependencies.isLoading || services.isLoading) return <Loading label="Reading the operational topology" />; const error = assets.error ?? dependencies.error ?? services.error; if (error) return <ErrorState error={error} />;
  const located = assets.data!.flatMap((asset) => { const location = locationOf(asset); return location ? [location] : []; }); const locations = new Map(located.map((asset) => [asset.id, asset])); const mapDependencies = dependencies.data!.filter((dependency) => locations.has(dependency.sourceAssetId) && locations.has(dependency.targetAssetId));
  return <><PageHeading eyebrow="Phase 26 / topology & geospatial intelligence" title="Operational map" copy="Infrastructure relationships and locations from your stored asset data. Assets without supplied coordinates are never placed on the map." />
    <section className="topology-facts"><span><Network size={16} /><b>{assets.data!.length}</b> stored assets</span><span><Route size={16} /><b>{dependencies.data!.length}</b> relationships</span><span><MapPinned size={16} /><b>{located.length}</b> mapped locations</span><span><Satellite size={16} /><b>{services.data!.length}</b> critical services</span></section>
    <section className="data-panel geo-map"><header><div><span className="panel-label">User-provided coordinates only</span><h2>Geospatial exposure view</h2></div></header>{located.length ? <div className="world-grid"><svg viewBox="0 0 1000 500" preserveAspectRatio="none" aria-hidden="true">{mapDependencies.map((dependency) => { const source = locations.get(dependency.sourceAssetId)!; const target = locations.get(dependency.targetAssetId)!; return <line key={dependency.id} x1={(source.longitude + 180) / 360 * 1000} y1={(90 - source.latitude) / 180 * 500} x2={(target.longitude + 180) / 360 * 1000} y2={(90 - target.latitude) / 180 * 500} />; })}</svg>{located.map((asset) => <button className={`geo-node geo-node--${asset.criticality}`} key={asset.id} style={{ left: `${(asset.longitude + 180) / 360 * 100}%`, top: `${(90 - asset.latitude) / 180 * 100}%` }} title={`${asset.name}${asset.siteName ? ` / ${asset.siteName}` : ""}`}><i /><span>{asset.name}</span></button>)}</div> : <Empty title="No mapped asset locations" copy="Add latitude and longitude when creating an asset, or import them into the asset metadata through an approved inventory workflow." />}</section>
    <section className="data-panel topology-table"><header><div><span className="panel-label">Location evidence</span><h2>Mapped assets</h2></div></header>{located.length ? <div className="table-wrap"><table><thead><tr><th>Asset</th><th>Site</th><th>Coordinates</th><th>Criticality</th></tr></thead><tbody>{located.map((asset) => <tr key={asset.id}><td><b>{asset.name}</b></td><td>{asset.siteName ?? "Not provided"}</td><td className="mono">{asset.latitude.toFixed(5)}, {asset.longitude.toFixed(5)}</td><td><Severity value={asset.criticality} /></td></tr>)}</tbody></table></div> : null}</section>
  </>;
}
