import { Pool } from "pg";
import { z } from "zod";
import { loadConfig } from "./config.js";

const inputSchema = z.object({
  organizationId: z.string().uuid(),
  email: z.string().trim().toLowerCase().pipe(z.email()),
  displayName: z.string().trim().min(2).max(120),
});

const input = inputSchema.parse({ organizationId: process.argv[2], email: process.argv[3], displayName: process.argv.slice(4).join(" ") });
const config = loadConfig();
if (!config.DATABASE_URL) throw new Error("DATABASE_URL is required for identity bootstrap.");
const pool = new Pool({ connectionString: config.DATABASE_URL });
const client = await pool.connect();
try {
  await client.query("BEGIN");
  await client.query("SELECT pg_advisory_xact_lock(1128355022)");
  const organization = await client.query("SELECT name FROM organizations WHERE id=$1", [input.organizationId]);
  if (!organization.rowCount) throw new Error("Organization not found.");
  const existing = await client.query("SELECT 1 FROM memberships m JOIN identity_users u ON u.id=m.user_id WHERE m.organization_id=$1", [input.organizationId]);
  if (existing.rowCount) throw new Error("Identity bootstrap is closed because this organization already has an enrolled identity.");
  const created = await client.query("INSERT INTO identity_users (email,display_name) VALUES ($1,$2) RETURNING id", [input.email, input.displayName]);
  const userId = String(created.rows[0].id);
  await client.query("INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,'organization_admin')", [input.organizationId, userId]);
  await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'identity.bootstrap_completed','identity_user',$2,$3)", [input.organizationId, userId, JSON.stringify({ email: input.email, role: "organization_admin" })]);
  await client.query("COMMIT");
  process.stdout.write(`Enrolled ${input.email} as organization_admin for ${String(organization.rows[0].name)}.\n`);
} catch (error) {
  await client.query("ROLLBACK");
  throw error;
} finally {
  client.release();
  await pool.end();
}
