CREATE TABLE vulnerabilities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid NOT NULL,
  external_id text NOT NULL,
  title text NOT NULL,
  cvss_score numeric(3,1) NOT NULL CHECK (cvss_score BETWEEN 0 AND 10),
  exploit_status text NOT NULL CHECK (exploit_status IN ('none_known','proof_of_concept','active_exploitation')),
  status text NOT NULL CHECK (status IN ('open','mitigated','accepted')),
  source_urls text[] NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, asset_id) REFERENCES assets(organization_id, id),
  UNIQUE (organization_id, asset_id, external_id)
);

CREATE TABLE critical_services (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  description text NOT NULL,
  criticality text NOT NULL CHECK (criticality IN ('low','medium','high','critical')),
  recovery_time_minutes integer NOT NULL CHECK (recovery_time_minutes > 0),
  maximum_tolerable_downtime_minutes integer NOT NULL CHECK (maximum_tolerable_downtime_minutes >= recovery_time_minutes),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name),
  UNIQUE (organization_id, id)
);

CREATE TABLE critical_service_assets (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  service_id uuid NOT NULL,
  asset_id uuid NOT NULL,
  PRIMARY KEY (service_id, asset_id),
  FOREIGN KEY (organization_id, service_id) REFERENCES critical_services(organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, asset_id) REFERENCES assets(organization_id, id)
);

CREATE TABLE risk_analyses (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  generated_at timestamptz NOT NULL,
  result jsonb NOT NULL,
  created_by uuid NOT NULL
);

CREATE INDEX vulnerabilities_org_asset_idx ON vulnerabilities (organization_id, asset_id, status);
CREATE INDEX service_assets_org_asset_idx ON critical_service_assets (organization_id, asset_id);
CREATE INDEX risk_analyses_org_generated_idx ON risk_analyses (organization_id, generated_at DESC);

CREATE TRIGGER risk_analyses_append_only BEFORE UPDATE OR DELETE ON risk_analyses
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
