import fs from "node:fs";
import path from "node:path";
import { scanProject, verdict } from "../src/launch-check";

const root = process.argv[2];
if (!root) { console.error("usage: tsx showcase/scan-dir.ts <project-dir>"); process.exit(2); }
const files: Array<{ path: string; text: string }> = [];
const walk = (d: string) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    if (e.isSymbolicLink() || ["node_modules", ".git", "dist"].includes(e.name)) continue;
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (fs.statSync(p).size < 1_000_000) files.push({ path: path.relative(root, p), text: fs.readFileSync(p, "utf8") });
  }
};
walk(root);
const f = scanProject(files);
const by = (s: string) => f.filter((x) => x.severity === s).length;
console.log(`files=${files.length} verdict=${verdict(f)} high=${by("high")} medium=${by("medium")} low=${by("low")}`);
for (const x of f.filter((x) => x.severity !== "low")) console.log(`${x.severity.toUpperCase()} ${x.rule} ${x.file}:${x.line} ${x.message}`);
const lows: Record<string, number> = {};
for (const x of f.filter((x) => x.severity === "low")) lows[x.rule] = (lows[x.rule] ?? 0) + 1;
console.log("low:", JSON.stringify(lows));
