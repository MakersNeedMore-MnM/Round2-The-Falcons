CREATE TABLE decision_proofs (
  decision_id uuid PRIMARY KEY REFERENCES response_decisions(id),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  evidence_hash text NOT NULL CHECK (evidence_hash ~ '^[a-f0-9]{64}$'),
  approver_wallet_address text NOT NULL,
  signature text NOT NULL,
  tx_hash text,
  contract_address text,
  block_number bigint,
  mstscan_url text,
  anchor_status text NOT NULL CHECK (anchor_status IN ('pending','confirmed','failed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  confirmed_at timestamptz
);
