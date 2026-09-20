import { ArrowDownRight, ArrowRight, CheckCircle2, Network, Radar, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { Brand } from "../components/Brand";
import { ResilienceScene } from "../components/ResilienceScene";

const capabilities = [
  { number: "01", title: "See the system", copy: "Map assets, dependencies, services, vulnerabilities, and the paths that connect operational risk.", icon: Network, to: "/app/assets" },
  { number: "02", title: "Read the signal", copy: "Turn live SIEM, EDR, STIX, and TAXII evidence into explainable findings without trusting source instructions.", icon: Radar, to: "/app/detection" },
  { number: "03", title: "Command the response", copy: "Run incidents through governed decisions, durable evidence, SLA ownership, and multi-operator approval.", icon: ShieldCheck, to: "/app/incidents" },
];

const operationalChapters = [
  { label: "Inventory / the known surface", to: "/app/assets" },
  { label: "Telemetry / the arriving signal", to: "/app/integrations" },
  { label: "Detection / the explainable anomaly", to: "/app/detection" },
  { label: "Incidents / the durable command", to: "/app/incidents" },
  { label: "Response / the governed decision", to: "/app/responses" },
];

export function LandingPage() {
  return <main className="landing">
    <div className="sanctuary-backdrop" aria-hidden="true"><i /><i /><i /></div>
    <ResilienceScene />
    <div className="grain" />
    <header className="landing-nav">
      <Brand />
      <nav aria-label="Primary navigation"><a href="#platform">Platform</a><a href="#control">Control</a><Link className="nav-cta" to="/connect">Open console <ArrowDownRight size={14} /></Link></nav>
    </header>
    <aside className="chapter-index" aria-label="Page chapters"><span>01</span><i /><span>05</span></aside>
    <section className="hero">
      <div className="hero-copy reveal-in">
        <p className="eyebrow"><span className="live-dot" /> Critical infrastructure / resilience intelligence</p>
        <h1>Know the path.<br /><em>Govern the outcome.</em></h1>
        <p className="hero-lead">Cascadia unifies real telemetry, operational topology, explainable detection, and human-governed incident response in one living system.</p>
        <div className="hero-actions"><Link className="button button--primary" to="/connect">Enter operations <ArrowRight size={16} /></Link><a className="text-link" href="#platform">Explore the system <ArrowDownRight size={15} /></a></div>
      </div>
      <div className="hero-orbit-card glass-panel reveal-in">
        <span className="panel-kicker">System posture</span><strong>Human control<br />remains absolute.</strong>
        <ul><li><CheckCircle2 size={13} /> Real telemetry only</li><li><CheckCircle2 size={13} /> Explainable ML findings</li><li><CheckCircle2 size={13} /> No autonomous execution</li></ul>
      </div>
      <div className="chapter-rail" aria-label="Platform chapters">
        {capabilities.map(({ number, title, copy, to }) => <Link to={to} key={number}><span>{number}</span><div><b>{title}</b><small>{copy}</small></div></Link>)}
      </div>
      <div className="hero-word" aria-hidden="true">CASCADIA</div>
    </section>
    <section className="threshold-section" id="threshold">
      <div className="chapter-meta"><span>01 — The threshold</span><b>Signal becomes consequence</b></div>
      <div className="threshold-grid">
        <h2>Silent drift.<br />Compromised trust.<br /><em>One path left open.</em></h2>
        <div><p className="lead">Cascadia begins where dashboards stop: at the boundary between a security signal and an operational consequence.</p><p>It reads the topology around each event, preserves the evidence behind every finding, and shows the route risk may take before a person decides what happens next.</p><a className="text-link" href="#platform">Cross the threshold <ArrowDownRight size={15} /></a></div>
      </div>
      <div className="threshold-stats"><span><b>07</b> intelligence phases</span><span><b>00</b> autonomous actions</span><span><b>∞</b> evidence continuity</span></div>
    </section>
    <section className="platform-section" id="platform">
      <div className="section-heading"><p className="eyebrow">The resilience plane</p><h2>One continuous view from signal to decision.</h2></div>
      <div className="capability-grid">
        {capabilities.map(({ number, title, copy, icon: Icon, to }) => <Link className="capability-card" to={to} key={number}><div className="card-top"><span>{number}</span><Icon size={23} /></div><h3>{title}</h3><p>{copy}</p><i /></Link>)}
      </div>
    </section>
    <section className="field-notes">
      <div className="field-window"><span>Live resilience plane</span><b>Observe the system beneath the signal.</b></div>
      <div className="field-directory">
        <p className="eyebrow">Five operational chapters</p>
        {operationalChapters.map(({ label, to }, index) => <Link to={to} key={label}><span>{String(index + 1).padStart(2, "0")}</span><h3>{label}</h3><ArrowRight size={14} /></Link>)}
      </div>
    </section>
    <section className="control-section" id="control">
      <div className="control-moon" aria-hidden="true" />
      <span className="chapter-number" aria-hidden="true">05</span>
      <p className="eyebrow">Designed around consequence</p>
      <h2>Intelligence proposes.<br /><em>People decide.</em></h2>
      <div className="control-facts"><span><b>00</b> autonomous actions</span><span><b>100%</b> evidence traceability</span><span><b>IST</b> operational timeline</span></div>
      <Link className="button button--ghost" to="/connect">Connect to Cascadia <ArrowRight size={16} /></Link>
    </section>
    <footer><Brand compact /><p>Safety-governed cyber resilience for critical infrastructure.</p><span>Phase 8 / Cinematic operations interface</span></footer>
  </main>;
}
