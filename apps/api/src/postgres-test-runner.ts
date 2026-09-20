import { spawnSync } from "node:child_process";

const result = spawnSync(process.execPath, ["--test", "dist/postgres-integration.test.js"], {
  stdio: "inherit",
  env: { ...process.env, RUN_POSTGRES_TESTS: "1" },
});

process.exitCode = result.status ?? 1;
