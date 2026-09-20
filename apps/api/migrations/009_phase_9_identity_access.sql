CREATE TABLE identity_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 2 AND 120),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identity_subjects (
  issuer text NOT NULL,
  subject text NOT NULL,
  user_id uuid NOT NULL REFERENCES identity_users(id),
  bound_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  PRIMARY KEY (issuer, subject),
  UNIQUE (issuer, user_id)
);

CREATE TABLE oidc_login_attempts (
  state_hash text PRIMARY KEY,
  code_verifier text NOT NULL,
  nonce text NOT NULL,
  return_to text NOT NULL CHECK (return_to LIKE '/%'),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identity_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  csrf_token_hash text NOT NULL,
  user_id uuid NOT NULL REFERENCES identity_users(id),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  role text NOT NULL CHECK (role IN ('platform_admin','organization_admin','incident_commander','security_analyst','ot_engineer','auditor','viewer')),
  mfa_verified boolean NOT NULL CHECK (mfa_verified),
  issuer text NOT NULL,
  subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revoke_reason text,
  FOREIGN KEY (organization_id, user_id) REFERENCES memberships(organization_id, user_id)
);

CREATE INDEX identity_sessions_active_idx ON identity_sessions (token_hash, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX identity_sessions_user_idx ON identity_sessions (user_id, created_at DESC);
CREATE INDEX oidc_login_attempts_expiry_idx ON oidc_login_attempts (expires_at);
CREATE UNIQUE INDEX identity_users_email_idx ON identity_users (lower(email));
