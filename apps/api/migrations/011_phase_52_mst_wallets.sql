ALTER TABLE identity_users
  ADD COLUMN wallet_address text,
  ADD COLUMN wallet_verified_at timestamptz;

CREATE UNIQUE INDEX identity_users_wallet_address_idx
  ON identity_users (lower(wallet_address))
  WHERE wallet_address IS NOT NULL;
