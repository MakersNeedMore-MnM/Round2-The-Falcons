import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Pool } from "pg";
import { loadConfig } from "./config.js";

const config = loadConfig();
if (!config.DATABASE_URL) throw new Error("DATABASE_URL is required to run migrations.");
const pool = new Pool({ connectionString: config.DATABASE_URL });

try {
  await pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  const directory = resolve(process.cwd(), "migrations");
  const files = (await readdir(directory)).filter((file) => file.endsWith(".sql")).toSorted();
  for (const file of files) {
    const applied = await pool.query("SELECT 1 FROM schema_migrations WHERE name=$1", [file]);
    if (applied.rowCount) continue;
    const sql = await readFile(resolve(directory, file), "utf8");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(1128355021)");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
} finally {
  await pool.end();
}
