ALTER TABLE risk_analyses ADD CONSTRAINT risk_analyses_org_id_unique UNIQUE (organization_id, id);

CREATE TABLE response_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  action_type text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('prohibited','recommend_only','operator_approved')),
  maximum_operational_impact integer NOT NULL CHECK (maximum_operational_impact BETWEEN 0 AND 100),
  minimum_approvals integer NOT NULL CHECK (minimum_approvals BETWEEN 1 AND 5),
  approval_roles text[] NOT NULL,
  requires_rollback_plan boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, action_type)
);

CREATE TABLE response_scenarios (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  analysis_id uuid NOT NULL,
  incident_id uuid NOT NULL,
  generated_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('awaiting_decision','awaiting_approval','approved','rejected','blocked')),
  result jsonb NOT NULL,
  created_by uuid NOT NULL,
  FOREIGN KEY (organization_id, analysis_id) REFERENCES risk_analyses(organization_id, id),
  UNIQUE (organization_id, id)
);

CREATE TABLE response_decisions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  scenario_id uuid NOT NULL,
  option_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  actor_role text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('approve','reject')),
  comment text NOT NULL,
  decided_at timestamptz NOT NULL,
  FOREIGN KEY (organization_id, scenario_id) REFERENCES response_scenarios(organization_id, id),
  UNIQUE (scenario_id, option_id, actor_user_id)
);

CREATE INDEX response_scenarios_org_generated_idx ON response_scenarios (organization_id, generated_at DESC);
CREATE INDEX response_decisions_scenario_idx ON response_decisions (organization_id, scenario_id, decided_at);

CREATE TRIGGER response_decisions_append_only BEFORE UPDATE OR DELETE ON response_decisions
FOR EACH ROW EXECUTE FUNCTION reject_append_only_mutation();
