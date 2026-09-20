CREATE TABLE integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 120),
  provider text NOT NULL CHECK (provider IN ('generic_webhook','splunk','microsoft_sentinel','elastic_security','crowdstrike','microsoft_defender','taxii')),
  data_type text NOT NULL CHECK (data_type IN ('security_events','stix_bundle')),
  event_source text CHECK (event_source IN ('siem','edr')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  secret_ciphertext text NOT NULL,
  secret_version integer NOT NULL DEFAULT 1 CHECK (secret_version > 0),
  last_delivery_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((data_type = 'security_events' AND event_source IS NOT NULL) OR (data_type = 'stix_bundle' AND event_source IS NULL)),
  UNIQUE (organization_id, name),
  UNIQUE (organization_id, id)
);

CREATE TABLE integration_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  integration_id uuid NOT NULL,
  external_delivery_id text NOT NULL CHECK (char_length(external_delivery_id) BETWEEN 1 AND 200),
  payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
  event_count integer NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  indicator_count integer NOT NULL DEFAULT 0 CHECK (indicator_count >= 0),
  received_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, integration_id) REFERENCES integrations(organization_id, id),
  UNIQUE (integration_id, external_delivery_id)
);

CREATE TABLE threat_indicators (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  integration_id uuid NOT NULL,
  stix_id text NOT NULL,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  pattern text NOT NULL,
  confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  labels text[] NOT NULL DEFAULT '{}',
  source_urls text[] NOT NULL DEFAULT '{}',
  valid_from timestamptz NOT NULL,
  valid_until timestamptz,
  modified_at timestamptz NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  CHECK (valid_until IS NULL OR valid_until > valid_from),
  FOREIGN KEY (organization_id, integration_id) REFERENCES integrations(organization_id, id),
  UNIQUE (organization_id, stix_id)
);

CREATE INDEX integrations_org_status_idx ON integrations (organization_id, status);
CREATE INDEX integration_deliveries_org_received_idx ON integration_deliveries (organization_id, received_at DESC);
CREATE INDEX threat_indicators_org_validity_idx ON threat_indicators (organization_id, valid_from DESC);

CREATE TRIGGER integration_deliveries_append_only BEFORE UPDATE OR DELETE ON integration_deliveries
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
