import { spawn } from "node:child_process";

const api = spawn(process.execPath, ["--env-file=.env", "apps/api/dist/server.js"], { stdio: "inherit" });
const web = process.platform === "win32"
  ? spawn(process.env.ComSpec ?? "cmd.exe", ["/d", "/s", "/c", "npm.cmd", "run", "dev", "-w", "@cascadia/web"], { stdio: "inherit" })
  : spawn("npm", ["run", "dev", "-w", "@cascadia/web"], { stdio: "inherit" });
const children = [api, web];
let closing = false;
function close(code = 0) {
  if (closing) return;
  closing = true;
  for (const child of children) if (!child.killed) child.kill();
  process.exitCode = code;
}
process.on("SIGINT", () => close());
process.on("SIGTERM", () => close());
for (const child of children) child.on("exit", (code) => { if (!closing) close(code ?? 1); });
async function waitFor(url, attempts = 40) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try { const response = await fetch(url); if (response.status < 500) return response; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return undefined;
}

void (async () => {
  const [apiResponse, webResponse] = await Promise.all([waitFor("http://127.0.0.1:3000/health"), waitFor("http://127.0.0.1:5173")]);
  if (apiResponse) process.stdout.write("Cascadia API ready: http://127.0.0.1:3000\n");
  else process.stderr.write("Cascadia API did not become ready. Check the API output above.\n");
  if (webResponse) process.stdout.write("Cascadia frontend ready: http://127.0.0.1:5173\n");
  else process.stderr.write("Cascadia frontend did not become ready. Check the Vite output above.\n");
  try {
    const readiness = await fetch("http://127.0.0.1:3000/health/ready");
    if (!readiness.ok) process.stderr.write("PostgreSQL is not ready. Start it and apply migrations before using the console.\n");
  } catch {}
})();
