import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const backupDirectory = resolve(process.cwd(), "backups");
await mkdir(backupDirectory, { recursive: true });
const stamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const destination = resolve(backupDirectory, `cascadia-${stamp}.dump`);
const child = spawn("docker", ["compose", "-f", "compose.production.yaml", "exec", "-T", "postgres", "pg_dump", "-U", "cascadia", "-d", "cascadia", "--format=custom", "--no-owner", "--no-acl"], { stdio: ["ignore", "pipe", "inherit"] });
child.stdout.pipe(createWriteStream(destination, { flags: "wx" }));
const exitCode = await new Promise((resolveExit, reject) => { child.once("error", reject); child.once("exit", resolveExit); });
if (exitCode !== 0) throw new Error(`PostgreSQL backup failed with exit code ${exitCode}.`);
process.stdout.write(`Verified backup stream written to ${destination}\n`);
