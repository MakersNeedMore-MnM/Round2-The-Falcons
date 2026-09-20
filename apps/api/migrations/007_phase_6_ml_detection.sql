ALTER TABLE normalized_security_events
ADD CONSTRAINT normalized_security_events_org_id_unique UNIQUE (organization_id, id);

CREATE TABLE detection_models (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  version integer NOT NULL CHECK (version > 0),
  status text NOT NULL CHECK (status IN ('active','retired')),
  algorithm text NOT NULL CHECK (algorithm = 'explainable_frequency_baseline_v1'),
  trained_at timestamptz NOT NULL,
  training_event_count integer NOT NULL CHECK (training_event_count >= 20),
  finding_threshold integer NOT NULL CHECK (finding_threshold BETWEEN 40 AND 95),
  result jsonb NOT NULL,
  UNIQUE (organization_id, version),
  UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX detection_models_one_active_per_org_idx
ON detection_models (organization_id)
WHERE status = 'active';

CREATE TABLE anomaly_findings (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  model_id uuid NOT NULL,
  event_id uuid NOT NULL,
  anomaly_score integer NOT NULL CHECK (anomaly_score BETWEEN 0 AND 100),
  level text NOT NULL CHECK (level IN ('low','medium','high','critical')),
  disposition text NOT NULL DEFAULT 'new' CHECK (disposition IN ('new','acknowledged','dismissed','escalated')),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  FOREIGN KEY (organization_id, model_id) REFERENCES detection_models(organization_id, id),
  FOREIGN KEY (organization_id, event_id) REFERENCES normalized_security_events(organization_id, id),
  UNIQUE (organization_id, model_id, event_id),
  UNIQUE (organization_id, id)
);

CREATE TABLE anomaly_finding_reviews (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  analyst_user_id uuid NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('acknowledged','dismissed','escalated')),
  comment text NOT NULL CHECK (char_length(comment) BETWEEN 1 AND 2000),
  reviewed_at timestamptz NOT NULL,
  FOREIGN KEY (organization_id, finding_id) REFERENCES anomaly_findings(organization_id, id)
);

CREATE TABLE detection_event_evaluations (
  organization_id uuid NOT NULL,
  model_id uuid NOT NULL,
  event_id uuid NOT NULL,
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, model_id, event_id),
  FOREIGN KEY (organization_id, model_id) REFERENCES detection_models(organization_id, id),
  FOREIGN KEY (organization_id, event_id) REFERENCES normalized_security_events(organization_id, id)
);

CREATE INDEX detection_models_org_trained_idx ON detection_models (organization_id, trained_at DESC);
CREATE INDEX anomaly_findings_org_created_idx ON anomaly_findings (organization_id, created_at DESC);
CREATE INDEX anomaly_findings_org_disposition_idx ON anomaly_findings (organization_id, disposition, created_at DESC);

CREATE TRIGGER anomaly_finding_reviews_append_only BEFORE UPDATE OR DELETE ON anomaly_finding_reviews
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();

CREATE TRIGGER detection_event_evaluations_append_only BEFORE UPDATE OR DELETE ON detection_event_evaluations
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
