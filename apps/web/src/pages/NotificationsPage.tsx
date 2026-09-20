import { useMutation } from "@tanstack/react-query";
import { BellRing, Send, Stamp } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "../api";
import { ErrorState, PageHeading, time } from "../components/Ui";

export function NotificationsPage() {
  const [result, setResult] = useState<string>(); const [title, setTitle] = useState(""); const [message, setMessage] = useState("");
  const delivery = useMutation({
    mutationFn: api.deliverNotification,
    onSuccess: (value) => setResult(`Delivered to ${value.provider} at ${time(value.deliveredAt)}.`),
  });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setResult(undefined);
    delivery.mutate({ title, message });
  };
  const templates = [{ label: "Incident update", title: "Incident update", message: "An incident is under active investigation. Review the operations console for the current evidence and assigned actions." }, { label: "Maintenance notice", title: "Planned maintenance notice", message: "A planned maintenance activity is scheduled. Validate operational impact and approved change records before proceeding." }, { label: "Executive brief", title: "Operational resilience brief", message: "A human-reviewed operational update is available. Review the evidence, risk context, and approved decisions in Cascadia." }];
  return <><PageHeading eyebrow="Phase 34 / operator notifications" title="Operator notification relay" copy="Choose a template, review its text, and send only when you explicitly approve. Cascadia never schedules, escalates, or sends a notification itself." />
    <section className="notification-layout"><aside className="data-panel notification-templates"><header><div><span className="panel-label">Operator templates</span><h2>Start with a draft</h2></div><Stamp size={18} /></header>{templates.map((template) => <button type="button" key={template.label} onClick={() => { setTitle(template.title); setMessage(template.message); setResult(undefined); }}><b>{template.label}</b><span>Load editable draft</span></button>)}</aside><section className="data-panel notification-panel"><header><div><span className="panel-label">Manual delivery only</span><h2>Review and send</h2></div><BellRing size={18} /></header><form className="config-body" onSubmit={submit}><label>Title<input value={title} onChange={(event) => setTitle(event.target.value)} required minLength={2} maxLength={200} placeholder="Incident update" /></label><label>Message<textarea value={message} onChange={(event) => setMessage(event.target.value)} required minLength={2} maxLength={4000} rows={6} placeholder="Describe the operator-approved update." /></label><p className="notification-note">Configure <code>NOTIFICATION_WEBHOOK_URL</code> and <code>NOTIFICATION_WEBHOOK_PROVIDER</code> in the API environment before delivery. This action never schedules or automates a message.</p>{delivery.error && <ErrorState error={delivery.error} />}{result && <p className="config-success">{result}</p>}<button className="button button--primary" disabled={delivery.isPending}><Send size={14} />{delivery.isPending ? "Delivering" : "Send manual notification"}</button></form></section></section>
  </>;
}
