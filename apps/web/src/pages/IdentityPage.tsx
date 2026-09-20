import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, UserPlus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "../api";
import { Empty, ErrorState, Loading, PageHeading } from "../components/Ui";
import { getInjectedSigner } from "../wallet-signer";

const roles = ["organization_admin", "incident_commander", "security_analyst", "ot_engineer", "auditor", "viewer"] as const;

export function IdentityPage() {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const users = useQuery({ queryKey: ["identity-users"], queryFn: api.identityUsers });
  const enroll = useMutation({ mutationFn: api.enrollIdentity, onSuccess: () => { void client.invalidateQueries({ queryKey: ["identity-users"] }); setOpen(false); } });
  const registerWallet = async (userId: string) => {
    const signer = getInjectedSigner();
    if (!signer) throw new Error("Install BridgeKey or MetaMask with EIP-1193 support.");
    const address = await signer.connect();
    const challenge = await api.walletChallenge(userId, address);
    const signature = await signer.signMessage(challenge.challenge);
    await api.walletVerify(userId, address, signature);
    await client.invalidateQueries({ queryKey: ["identity-users"] });
  };
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    enroll.mutate({ email: String(data.get("email")), displayName: String(data.get("displayName")), role: String(data.get("role")) as typeof roles[number] });
  };
  if (users.isLoading) return <Loading label="Reading identity access" />;
  if (users.error) return <ErrorState error={users.error} retry={() => void users.refetch()} />;
  return <><PageHeading eyebrow="Phase 9 / zero-trust access" title="Identity access" copy="Pre-enroll verified people and least-privilege roles before their first MFA-backed SSO session." action={<button className="button button--primary" onClick={() => setOpen(true)}><UserPlus size={14} /> Enroll identity</button>} />
    <section className="data-panel identity-boundary"><header><div><span className="panel-label">Enforcement boundary</span><h2>Production access policy</h2></div><ShieldCheck size={18} /></header><div><span><b>SSO</b> Authorization Code + PKCE</span><span><b>MFA</b> Verified by identity claims</span><span><b>Session</b> Opaque and revocable</span><span><b>CSRF</b> Required on mutations</span></div></section>
    <section className="data-panel table-panel"><header><div><span className="panel-label">Enrolled people</span><h2>Organization access / {users.data!.length}</h2></div></header>{users.data!.length ? <div className="table-wrap"><table><thead><tr><th>Identity</th><th>Role</th><th>Status</th><th>Wallet proof</th></tr></thead><tbody>{users.data!.map(({ user, role }) => <tr key={user.id}><td><b>{user.displayName}</b><small>{user.email}</small></td><td>{role.replaceAll("_", " ")}</td><td><span className={`connection connection--${user.status}`}>{user.status}</span></td><td>{user.walletAddress ? <span className="mono">{user.walletAddress.slice(0, 10)}…</span> : <button onClick={() => void registerWallet(user.id)}>Verify wallet</button>}</td></tr>)}</tbody></table></div> : <Empty title="No SSO identities enrolled" copy="Enroll a verified company email before the person attempts enterprise sign-in." />}</section>
    {open && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setOpen(false); }}><form className="modal" onSubmit={submit}><p className="eyebrow">Administrator-controlled enrollment</p><h2>Enroll identity</h2><label>Verified work email<input name="email" type="email" autoComplete="email" required /></label><label>Display name<input name="displayName" minLength={2} autoComplete="name" required /></label><label>Least-privilege role<select name="role" defaultValue="security_analyst">{roles.map((role) => <option key={role} value={role}>{role.replaceAll("_", " ")}</option>)}</select></label>{enroll.error && <ErrorState error={enroll.error} />}<div className="modal-actions"><button type="button" onClick={() => setOpen(false)}>Cancel</button><button className="button button--primary" type="submit" disabled={enroll.isPending}>Enroll person</button></div></form></div>}
  </>;
}
