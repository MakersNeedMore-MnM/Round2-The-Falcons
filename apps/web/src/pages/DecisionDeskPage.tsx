import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ShieldAlert, XCircle } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import { ErrorState, Loading, PageHeading, Severity, time } from "../components/Ui";
import { getInjectedSigner } from "../wallet-signer";

function DecisionProofPanel({ incidentId, decision, currentUserId, walletAddress }: { incidentId: string; decision: { id: string; actorUserId: string; decision: "approve" | "reject" }; currentUserId?: string; walletAddress?: string }) {
  const client = useQueryClient();
  const proof = useQuery({ queryKey: ["decision-proof", incidentId, decision.id], queryFn: () => api.decisionProof(incidentId, decision.id), enabled: decision.decision === "approve" });
  const anchor = useMutation({
    mutationFn: async () => {
      const signer = getInjectedSigner();
      if (!signer) throw new Error("Install BridgeKey or MetaMask with EIP-1193 support to sign the proof.");
      const handoff = await api.decisionAnchor(incidentId, decision.id);
      await signer.connect();
      const signature = await signer.signMessage(handoff.evidenceHash);
      return api.submitDecisionAnchor(incidentId, decision.id, signature);
    },
    onSuccess: () => void client.invalidateQueries({ queryKey: ["decision-proof", incidentId, decision.id] }),
  });
  if (decision.decision !== "approve") return null;
  if (proof.isLoading) return <p className="proof-note">Reading decision proof status…</p>;
  if (proof.error && (proof.error as { status?: number }).status !== 404) return <p className="proof-note">Proof status unavailable until MST is configured.</p>;
  const canAnchor = currentUserId === decision.actorUserId;
  const canSign = canAnchor && Boolean(walletAddress);
  return <div className="proof-panel"><b>Decision proof</b><span>{proof.data ? `${proof.data.match ? "Verified" : "Mismatch"} · ${proof.data.offChainHash.slice(0, 18)}…` : "Not anchored"}</span>{canAnchor && !proof.data && <><span>{walletAddress ? `Registered wallet · ${walletAddress.slice(0, 10)}…` : "No verified wallet is registered for this approver."}</span>{canSign ? <button className="button button--primary" disabled={anchor.isPending} onClick={() => anchor.mutate()}>{anchor.isPending ? "Waiting for wallet signature…" : "Sign & anchor decision"}</button> : <a className="button" href="/app/identity">Verify wallet in Identity access</a>}</>}{proof.data?.match && <button onClick={() => void proof.refetch()}>Verify</button>}{anchor.error && <small>{(anchor.error as Error).message}</small>}</div>;
}

export function DecisionDeskPage() {
  const client = useQueryClient(); const scenarios = useQuery({ queryKey: ["responses"], queryFn: api.responses }); const browserSession = useQuery({ queryKey: ["auth-session"], queryFn: api.authSession }); const [comments, setComments] = useState<Record<string, string>>({});
  const decide = useMutation({ mutationFn: ({ scenarioId, optionId, decision, comment }: { scenarioId: string; optionId: string; decision: "approve" | "reject"; comment: string }) => api.decideResponse(scenarioId, { optionId, decision, comment }), onSuccess: () => client.invalidateQueries({ queryKey: ["responses"] }) });
  if (scenarios.isLoading) return <Loading label="Reading governed response scenarios" />; if (scenarios.error) return <ErrorState error={scenarios.error} />;
  const open = scenarios.data!.filter((scenario) => ["awaiting_decision", "awaiting_approval"].includes(scenario.status));
  const approved = scenarios.data!.filter((scenario) => scenario.status === "approved");
  return <><PageHeading eyebrow="Phase 20 / governed decisions" title="Response decision desk" copy="Approve or reject a policy-eligible recommendation with a recorded rationale. After approval, the approving operator can sign the decision with their verified wallet and anchor its proof on MST. Execution remains disabled." />
    <section className="decision-boundary"><ShieldAlert size={17} /><span>Every decision is attributable, policy-checked, and append-only. <b>Execution remains disabled.</b></span></section>
    <div className="decision-stack">{open.map((scenario) => <section className="data-panel" key={scenario.id}><header><div><span className="panel-label">Scenario {scenario.id.slice(0, 8)} / {time(scenario.generatedAt)}</span><h2>{scenario.status.replaceAll("_", " ")}</h2></div><span className={`disposition disposition--${scenario.status}`}>{scenario.decisions.length} recorded decisions</span></header><div className="decision-options">{scenario.options.map((option) => <article key={option.id}><div className="option-top"><div><b>{option.title}</b><small>{option.actionType.replaceAll("_", " ")} · {option.approvalMode.replaceAll("_", " ")}</small></div><Severity value={option.eligible ? "low" : "high"} /></div><p>{option.policyChecks.map((check) => check.reason).join(" ")}</p><div className="option-metrics"><span>Benefit <b>{option.securityBenefit}</b></span><span>Impact <b>{option.operationalImpact}</b></span><span>Residual <b>{option.residualRiskScore}</b></span><span>Approvals <b>{option.requiredApprovals}</b></span></div>{option.eligible ? <div className="decision-form"><textarea value={comments[option.id] ?? ""} onChange={(event) => setComments((current) => ({ ...current, [option.id]: event.target.value }))} placeholder="Required decision rationale" rows={2} /><div><button disabled={!comments[option.id]?.trim() || decide.isPending} onClick={() => decide.mutate({ scenarioId: scenario.id, optionId: option.id, decision: "reject", comment: comments[option.id]! })}><XCircle size={14} /> Reject</button><button className="button button--primary" disabled={!comments[option.id]?.trim() || decide.isPending} onClick={() => decide.mutate({ scenarioId: scenario.id, optionId: option.id, decision: "approve", comment: comments[option.id]! })}><CheckCircle2 size={14} /> Record approval</button></div></div> : <p className="blocked-copy">Blocked by policy; this option cannot be approved.</p>}</article>)}</div></section>)}{approved.map((scenario) => <section className="data-panel" key={scenario.id}><header><div><span className="panel-label">Approved scenario {scenario.id.slice(0, 8)}</span><h2>Decision proofs</h2></div></header>{scenario.decisions.filter((decision) => decision.decision === "approve").map((decision) => <DecisionProofPanel key={decision.id} incidentId={scenario.incidentId} decision={decision} currentUserId={browserSession.data?.user.id} walletAddress={browserSession.data?.user.walletAddress} />)}</section>)}{!open.length && !approved.length && <section className="data-panel empty"><span>00</span><h3>No response decisions</h3><p>New scenarios appear after an authorized operator runs a policy-governed response simulation.</p></section>}</div>
  </>;
}
