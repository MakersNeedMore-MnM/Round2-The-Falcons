CREATE TABLE audit_batch_anchors (
  id bigserial PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  batch_start_time timestamptz NOT NULL,
  batch_end_time timestamptz NOT NULL,
  event_count integer NOT NULL CHECK (event_count > 0),
  merkle_root text NOT NULL CHECK (merkle_root ~ '^[a-f0-9]{64}$'),
  tx_hash text,
  block_number bigint,
  mstscan_url text,
  anchor_status text NOT NULL CHECK (anchor_status IN ('pending','confirmed','failed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  confirmed_at timestamptz,
  UNIQUE (organization_id, batch_start_time, batch_end_time)
);

ALTER TABLE audit_events
  ADD COLUMN included_in_anchor_id bigint REFERENCES audit_batch_anchors(id);

CREATE INDEX audit_batch_anchors_org_created_idx
  ON audit_batch_anchors (organization_id, created_at DESC);

CREATE INDEX audit_events_anchor_idx
  ON audit_events (included_in_anchor_id);
