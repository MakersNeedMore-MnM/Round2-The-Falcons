import { AlertTriangle, LoaderCircle, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";

export function Loading({ label = "Reading the resilience plane" }: { label?: string }) { return <div className="state-panel"><LoaderCircle className="spin" size={18} /><span>{label}</span></div>; }
export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) { return <div className="state-panel state-panel--error"><AlertTriangle size={18} /><span>{error instanceof Error ? error.message : "The data plane could not be reached."}</span>{retry && <button onClick={retry}><RefreshCw size={13} /> Retry</button>}</div>; }
export function Empty({ title, copy }: { title: string; copy: string }) { return <div className="empty"><span>00</span><h3>{title}</h3><p>{copy}</p></div>; }
export function PageHeading({ eyebrow, title, copy, action }: { eyebrow: string; title: string; copy: string; action?: ReactNode }) { return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{copy}</p></div>{action}</div>; }
export function Severity({ value }: { value: string }) { return <span className={`severity severity--${value}`}>{value}</span>; }
export const displayTimeZone = "Asia/Kolkata";
export function time(value: string) { return new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short", timeZone: displayTimeZone }).format(new Date(value)) + " IST"; }
