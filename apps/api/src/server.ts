import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { PostgresCascadiaStore } from "./postgres-store.js";
import { InMemoryCascadiaStore } from "./store.js";
import { seedDemoData } from "./demo-seed.js";
import { createMstClient } from "./mst-client.js";
import { AuditAnchorService } from "./audit-anchor-service.js";

const config = loadConfig();
const store = config.DATA_STORE === "postgres" ? new PostgresCascadiaStore(config.DATABASE_URL!) : new InMemoryCascadiaStore();
if (config.DEMO_MODE) {
  if (!(store instanceof InMemoryCascadiaStore)) throw new Error("DEMO_MODE requires the in-memory data store.");
  await seedDemoData(store);
}
const app = buildApp(config, store);
let auditInterval: NodeJS.Timeout | undefined;
if (config.MST_DEPLOYER_PRIVATE_KEY && config.MST_CONTRACT_ADDRESS) {
  const auditAnchors = new AuditAnchorService(store, createMstClient(config));
  auditInterval = setInterval(() => {
    void store.listOrganizations().then((organizations) => Promise.all(organizations.map((organization) => auditAnchors.runAnchorBatch(organization.id)))).catch((error) => app.log.warn({ error }, "MST audit anchor sweep failed"));
  }, (config.MST_AUDIT_ANCHOR_INTERVAL_MINUTES ?? 60) * 60_000);
  auditInterval.unref();
}

app.addHook("onClose", async () => {
  if (auditInterval) clearInterval(auditInterval);
  if (store instanceof PostgresCascadiaStore) await store.close();
});

const address = await app.listen({ port: config.PORT, host: config.HOST });
app.log.info({ address }, "Cascadia API listening");

let closing = false;
async function shutdown(signal: string): Promise<void> {
  if (closing) return;
  closing = true;
  app.log.info({ signal }, "Graceful shutdown started");
  const deadline = setTimeout(() => process.exit(1), 10_000);
  deadline.unref();
  try { await app.close(); process.exitCode = 0; }
  catch (error) { app.log.error(error, "Graceful shutdown failed"); process.exitCode = 1; }
  finally { clearTimeout(deadline); }
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));
