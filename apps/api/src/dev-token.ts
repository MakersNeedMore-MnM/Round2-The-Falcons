import { createHmac, randomUUID } from "node:crypto";
import { userRoleSchema, type UserRole } from "@cascadia/contracts";
import { Pool } from "pg";
import { loadConfig } from "./config.js";

const config = loadConfig();
if (config.NODE_ENV === "production") throw new Error("Local access tokens cannot be issued in production.");
const role: UserRole = userRoleSchema.parse(process.argv[3] ?? "organization_admin");
const pool = config.DATABASE_URL ? new Pool({ connectionString: config.DATABASE_URL }) : undefined;
try {
  const requestedOrganizationId = process.argv[2];
  const demoOrganization = config.DEMO_MODE
    ? { id: requestedOrganizationId ?? "11111111-1111-4111-8111-111111111111", name: "Demo Critical Infrastructure Organization" }
    : undefined;
  if (!demoOrganization && !config.DATABASE_URL) throw new Error("DATABASE_URL is required to select a local organization.");
  const result = demoOrganization ? undefined : requestedOrganizationId
    ? await pool!.query("SELECT id,name FROM organizations WHERE id=$1", [requestedOrganizationId])
    : await pool!.query("SELECT id,name FROM organizations ORDER BY created_at DESC LIMIT 1");
  const selectedOrganization = demoOrganization ?? result?.rows[0] as { id: string; name: string } | undefined;
  if (!selectedOrganization) throw new Error(requestedOrganizationId ? "The requested organization does not exist." : "No organization exists. Onboard one before creating a local token.");
  const now = Math.floor(Date.now() / 1000);
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode({ sub: randomUUID(), organizationId: selectedOrganization.id, role, iat: now, exp: now + 8 * 60 * 60 });
  const signature = createHmac("sha256", config.JWT_SECRET).update(`${header}.${payload}`).digest("base64url");
  process.stdout.write(`Organization: ${selectedOrganization.name} (${selectedOrganization.id})\nRole: ${role}\nExpires: ${new Date((now + 8 * 60 * 60) * 1000).toISOString()}\n\n${header}.${payload}.${signature}\n`);
} finally {
  if (pool) await pool.end();
}
