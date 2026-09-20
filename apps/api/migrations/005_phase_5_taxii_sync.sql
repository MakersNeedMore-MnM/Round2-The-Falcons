CREATE TABLE taxii_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  integration_id uuid NOT NULL,
  name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 120),
  api_root_url text NOT NULL CHECK (api_root_url LIKE 'https://%/'),
  collection_id text NOT NULL CHECK (collection_id ~ '^[A-Za-z0-9._~-]{1,200}$'),
  authentication_type text NOT NULL CHECK (authentication_type IN ('none','basic','bearer')),
  authentication_ciphertext text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  checkpoint_added_after timestamptz,
  last_sync_at timestamptz,
  autonomous_scheduling_enabled boolean NOT NULL DEFAULT false CHECK (autonomous_scheduling_enabled = false),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((authentication_type = 'none' AND authentication_ciphertext IS NULL) OR (authentication_type <> 'none' AND authentication_ciphertext IS NOT NULL)),
  FOREIGN KEY (organization_id, integration_id) REFERENCES integrations(organization_id, id),
  UNIQUE (organization_id, name),
  UNIQUE (organization_id, id)
);

CREATE TABLE taxii_sync_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  source_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('running','succeeded','failed')),
  requested_by_user_id uuid NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  checkpoint_before timestamptz,
  checkpoint_after timestamptz,
  pages_fetched integer NOT NULL DEFAULT 0 CHECK (pages_fetched >= 0),
  objects_received integer NOT NULL DEFAULT 0 CHECK (objects_received >= 0),
  indicators_accepted integer NOT NULL DEFAULT 0 CHECK (indicators_accepted >= 0),
  error_code text,
  error_message text,
  FOREIGN KEY (organization_id, source_id) REFERENCES taxii_sources(organization_id, id),
  UNIQUE (organization_id, id)
);

CREATE TABLE taxii_sync_attempts (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  job_id uuid NOT NULL,
  page_number integer NOT NULL CHECK (page_number > 0),
  attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 3),
  status text NOT NULL CHECK (status IN ('succeeded','failed')),
  http_status integer CHECK (http_status BETWEEN 100 AND 599),
  error_code text,
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  FOREIGN KEY (organization_id, job_id) REFERENCES taxii_sync_jobs(organization_id, id),
  UNIQUE (job_id, page_number, attempt_number)
);

CREATE INDEX taxii_sources_org_status_idx ON taxii_sources (organization_id, status);
CREATE INDEX taxii_sync_jobs_source_started_idx ON taxii_sync_jobs (source_id, started_at DESC);
CREATE INDEX taxii_sync_attempts_job_page_idx ON taxii_sync_attempts (job_id, page_number, attempt_number);

CREATE TRIGGER taxii_sync_attempts_append_only BEFORE UPDATE OR DELETE ON taxii_sync_attempts
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
