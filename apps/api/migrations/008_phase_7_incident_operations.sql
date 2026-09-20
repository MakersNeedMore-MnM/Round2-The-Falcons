CREATE TABLE incidents (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  reference text NOT NULL,
  idempotency_key text NOT NULL,
  creation_fingerprint text NOT NULL CHECK (creation_fingerprint ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('new','triaged','investigating','contained','recovering','resolved','closed')),
  priority text NOT NULL CHECK (priority IN ('p1','p2','p3','p4')),
  severity text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  acknowledgement_due_at timestamptz NOT NULL,
  resolution_due_at timestamptz NOT NULL,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (organization_id, id),
  UNIQUE (organization_id, reference),
  UNIQUE (organization_id, idempotency_key)
);

CREATE TABLE incident_evidence (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  incident_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('security_event','anomaly_finding','risk_analysis','response_scenario','threat_indicator')),
  resource_id uuid NOT NULL,
  rationale text NOT NULL CHECK (char_length(rationale) BETWEEN 1 AND 4000),
  linked_by_user_id uuid NOT NULL,
  linked_at timestamptz NOT NULL,
  FOREIGN KEY (organization_id, incident_id) REFERENCES incidents(organization_id, id),
  UNIQUE (incident_id, kind, resource_id)
);

CREATE TABLE incident_timeline (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  incident_id uuid NOT NULL,
  type text NOT NULL CHECK (type IN ('incident_created','status_changed','assignment_changed','comment','evidence_linked','task_created','task_updated')),
  message text NOT NULL,
  actor_user_id uuid NOT NULL,
  occurred_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (organization_id, incident_id) REFERENCES incidents(organization_id, id)
);

CREATE TABLE incident_tasks (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  incident_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('todo','in_progress','blocked','done')),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  FOREIGN KEY (organization_id, incident_id) REFERENCES incidents(organization_id, id),
  UNIQUE (organization_id, incident_id, id)
);

CREATE INDEX incidents_org_updated_idx ON incidents (organization_id, updated_at DESC);
CREATE INDEX incidents_open_sla_idx ON incidents (organization_id, priority, resolution_due_at) WHERE status NOT IN ('resolved','closed');
CREATE INDEX incident_evidence_resource_idx ON incident_evidence (organization_id, kind, resource_id);
CREATE INDEX incident_timeline_incident_time_idx ON incident_timeline (incident_id, occurred_at);
CREATE INDEX incident_tasks_incident_status_idx ON incident_tasks (incident_id, status);

CREATE TRIGGER incident_evidence_append_only BEFORE UPDATE OR DELETE ON incident_evidence
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();

CREATE TRIGGER incident_timeline_append_only BEFORE UPDATE OR DELETE ON incident_timeline
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
