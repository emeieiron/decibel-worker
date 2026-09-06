import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import process from "node:process";

const allowedNames = new Set([
  "DECIBEL_NODE_API_KEY",
  "GAS_STATION_API_KEY",
  "SESSION_SIGNING_KEY",
]);

const name = process.argv[2];
if (!allowedNames.has(name)) {
  throw new Error("Pass one supported Worker secret name.");
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const value = Buffer.concat(chunks).toString("utf8").trim();
if (!value || value.includes("\n")) {
  throw new Error("The secret must be a non-empty, single-line value.");
}

const target = resolve(".dev.vars");
const temporary = `${target}.tmp`;
let lines = [];
try {
  lines = (await readFile(target, "utf8")).split(/\r?\n/).filter(Boolean);
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}

const replacement = `${name}=${value}`;
const existingIndex = lines.findIndex((line) => line.startsWith(`${name}=`));
if (existingIndex >= 0) lines[existingIndex] = replacement;
else lines.push(replacement);

await mkdir(dirname(target), { recursive: true });
await writeFile(temporary, `${lines.join("\n")}\n`, { mode: 0o600 });
await rename(temporary, target);
await chmod(target, 0o600);
process.stdout.write(`Stored ${name} in .dev.vars\n`);
