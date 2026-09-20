import { useQuery } from "@tanstack/react-query";
import { Activity, Database, RadioTower, TriangleAlert } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorState, Loading, PageHeading, time } from "../components/Ui";

export function DataQualityPage() {
  const report = useQuery({ queryKey: ["data-quality"], queryFn: api.dataQuality });
  if (report.isLoading) return <Loading label="Calculating stored-source freshness" />; if (report.error) return <ErrorState error={report.error} />;
  const data = report.data!;
  return <><PageHeading eyebrow="Phase 30 / data quality" title="Source freshness control" copy="A transparent view of data received through configured sources. Freshness is calculated only from durable signed-delivery records." />
    <section className="topology-facts quality-facts"><span><RadioTower size={16} /><b>{data.summary.activeSources}</b> active sources</span><span><Activity size={16} /><b>{data.summary.currentSources}</b> current</span><span><TriangleAlert size={16} /><b>{data.summary.staleSources}</b> stale</span><span><Database size={16} /><b>{data.summary.sourcesWithNoData}</b> no data</span></section>
    <section className="data-panel quality-table"><header><div><span className="panel-label">24-hour freshness policy</span><h2>Connector evidence</h2></div><small>Calculated {time(data.generatedAt)}</small></header>{data.sources.length ? <div className="table-wrap"><table><thead><tr><th>Source</th><th>Type</th><th>Latest delivery</th><th>Records</th><th>Freshness</th></tr></thead><tbody>{data.sources.map((source) => <tr key={source.sourceId}><td><b>{source.name}</b><small>{source.provider.replaceAll("_", " ")}</small></td><td>{source.dataType.replaceAll("_", " ")}</td><td>{source.mostRecentRecordAt ? time(source.mostRecentRecordAt) : "None"}</td><td className="mono">{source.recordsReceived}</td><td><span className={`connection connection--${source.freshness}`}>{source.freshness.replaceAll("_", " ")}</span></td></tr>)}</tbody></table></div> : <Empty title="No configured sources" copy="Create a signed connector before source freshness can be assessed." />}</section>
    <section className="data-panel quality-limitations"><header><div><span className="panel-label">Interpretation boundary</span><h2>What this report does not claim</h2></div></header><ul>{data.limitations.map((item) => <li key={item}>{item}</li>)}</ul></section>
  </>;
}
