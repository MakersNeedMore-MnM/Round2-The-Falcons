import { ArrowLeft, ArrowRight, KeyRound, LockKeyhole } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, session } from "../api";
import { Brand } from "../components/Brand";
import { ResilienceScene } from "../components/ResilienceScene";

export function ConnectPage() {
  const [token, setToken] = useState("");
  const navigate = useNavigate();
  const status = useQuery({ queryKey: ["auth-status"], queryFn: api.authStatus, retry: false });
  const localAccessAvailable = status.data?.localBearerEnabled ?? import.meta.env.DEV;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!token.trim()) return;
    session.set(token.trim());
    navigate("/app");
  };
  return <main className="connect-page"><ResilienceScene mode="console" /><header className="minimal-nav"><Brand /><Link to="/"><ArrowLeft size={15} /> Back to overview</Link></header>
    <section className="connect-card glass-panel"><div className="connect-icon"><KeyRound size={20} /></div><p className="eyebrow">Identity-governed access</p><h1>Enter the operations plane.</h1><p>Authenticate through your organization’s identity provider. Cascadia requires a pre-enrolled identity and verified multi-factor authentication.</p>
      {status.data?.oidcEnabled && <a className="button button--primary sso-button" href="/api/auth/login?returnTo=%2Fapp">Continue with enterprise SSO <ArrowRight size={16} /></a>}
      {status.data && !status.data.oidcEnabled && <div className="auth-notice"><LockKeyhole size={15} /><span>Enterprise SSO is not configured in this local environment.</span></div>}
      {status.error && <div className="auth-notice auth-notice--offline"><LockKeyhole size={15} /><span>The Cascadia API is offline. Start the complete local stack, then <button type="button" onClick={() => void status.refetch()}>retry connection</button>.</span></div>}
      {localAccessAvailable && <details className="local-access" open={Boolean(status.error)}><summary>Local development access</summary><form onSubmit={submit}><label htmlFor="access-token">Development bearer token</label><textarea id="access-token" value={token} onChange={(event) => setToken(event.target.value)} rows={4} autoComplete="off" spellCheck={false} placeholder="eyJhbGciOiJIUzI1NiIs…" required /><button className="button button--ghost" type="submit">Connect locally <ArrowRight size={16} /></button></form><small><LockKeyhole size={13} /> Development only: run <code>npm.cmd run dev:token</code>. This fallback is disabled in production.</small></details>}
      <small><LockKeyhole size={13} /> Production sessions use an opaque, revocable HttpOnly cookie. Provider tokens and credentials are never exposed to browser code.</small>
    </section>
  </main>;
}
