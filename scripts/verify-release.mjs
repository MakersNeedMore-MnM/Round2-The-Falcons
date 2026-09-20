import { spawnSync } from "node:child_process";

const command = process.platform === "win32" ? "npm.cmd" : "npm";
const run = (args) => {
  const result = process.platform === "win32"
    ? spawnSync("cmd.exe", ["/d", "/s", "/c", [command, ...args].join(" ")], { stdio: "inherit" })
    : spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
};

console.log("Checking local PostgreSQL container...");
const docker = spawnSync("docker", ["compose", "ps", "--status", "running", "postgres"], { encoding: "utf8" });
if (docker.status !== 0 || !docker.stdout.includes("postgres")) {
  console.error("PostgreSQL is not running. Start it with: docker compose up -d postgres");
  process.exit(1);
}

run(["run", "migrate", "-w", "@cascadia/api"]);
run(["run", "verify"]);
run(["run", "test:postgres"]);
console.log("Release verification passed: build, contracts, unit tests, and live PostgreSQL integration test are green.");
