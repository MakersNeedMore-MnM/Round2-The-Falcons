CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 120),
  sector text NOT NULL CHECK (sector IN ('healthcare','energy','water','transport','emergency_services','other')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  user_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('platform_admin','organization_admin','incident_commander','security_analyst','ot_engineer','auditor','viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE retention_policies (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id),
  raw_events_days integer NOT NULL CHECK (raw_events_days BETWEEN 1 AND 3650),
  normalized_events_days integer NOT NULL CHECK (normalized_events_days BETWEEN 1 AND 3650),
  audit_evidence_days integer NOT NULL CHECK (audit_evidence_days BETWEEN 365 AND 36500),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  client text NOT NULL CHECK (client IN ('ui','evaluator')),
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  external_id text NOT NULL,
  name text NOT NULL,
  asset_type text NOT NULL,
  criticality text NOT NULL,
  classification text NOT NULL,
  owner_user_id uuid,
  hostname text,
  ip_address inet,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, external_id),
  UNIQUE (organization_id, id)
);

CREATE TABLE asset_dependencies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  source_asset_id uuid NOT NULL,
  target_asset_id uuid NOT NULL,
  relationship text NOT NULL,
  protocol text,
  critical boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (source_asset_id <> target_asset_id),
  FOREIGN KEY (organization_id, source_asset_id) REFERENCES assets(organization_id, id),
  FOREIGN KEY (organization_id, target_asset_id) REFERENCES assets(organization_id, id),
  UNIQUE (organization_id, source_asset_id, target_asset_id, relationship)
);

CREATE TABLE normalized_security_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  source text NOT NULL CHECK (source IN ('siem','edr')),
  source_event_id text NOT NULL,
  event_type text NOT NULL,
  severity text NOT NULL,
  observed_at timestamptz NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  asset_external_ids text[] NOT NULL DEFAULT '{}',
  record jsonb NOT NULL,
  UNIQUE (organization_id, source, source_event_id)
);

CREATE TABLE published_posts (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  agent_id uuid NOT NULL REFERENCES agents(id),
  topic text NOT NULL,
  rationale text NOT NULL,
  source_urls text[] NOT NULL,
  published_at timestamptz NOT NULL
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  actor_user_id uuid,
  event_type text NOT NULL,
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX assets_org_criticality_idx ON assets (organization_id, criticality);
CREATE INDEX dependencies_org_source_idx ON asset_dependencies (organization_id, source_asset_id);
CREATE INDEX events_org_observed_idx ON normalized_security_events (organization_id, observed_at DESC);
CREATE INDEX posts_org_published_idx ON published_posts (organization_id, published_at DESC);
CREATE INDEX audit_org_occurred_idx ON audit_events (organization_id, occurred_at DESC);

CREATE FUNCTION reject_append_only_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER published_posts_append_only BEFORE UPDATE OR DELETE ON published_posts
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();

CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
