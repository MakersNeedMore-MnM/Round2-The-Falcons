CREATE TABLE legal_holds (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 200),
  rationale text NOT NULL CHECK (char_length(rationale) BETWEEN 2 AND 4000),
  status text NOT NULL CHECK (status IN ('active', 'released')),
  scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by_user_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  released_by_user_id uuid,
  released_at timestamptz,
  release_rationale text,
  CHECK ((status = 'active' AND released_at IS NULL AND released_by_user_id IS NULL) OR (status = 'released' AND released_at IS NOT NULL AND released_by_user_id IS NOT NULL AND release_rationale IS NOT NULL))
);
CREATE INDEX legal_holds_organization_status_idx ON legal_holds (organization_id, status, created_at DESC);
