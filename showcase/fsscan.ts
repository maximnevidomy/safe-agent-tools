// Filesystem helpers shared by the CLI and the app. Always confined to allowed roots.
import fs from "node:fs";
import path from "node:path";
import { scanProject, verdict, Finding } from "../src/launch-check";
import { scanText } from "../src/skill-scanner";

export function confine(input: string, roots: string[]): string {
  if (typeof input !== "string" || !input || input.includes("\0")) throw new Error("path is required");
  const real = fs.realpathSync(path.resolve(input)); // resolves symlinks first
  const ok = roots.some((r) => { const root = fs.realpathSync(r); return real === root || real.startsWith(root + path.sep); });
  if (!ok) throw new Error("path is outside the allowed folders (set DEMO_ROOTS)");
  if (!fs.statSync(real).isDirectory()) throw new Error("path is not a folder");
  return real;
}

export function readTree(root: string, filter: (name: string) => boolean, maxFiles = 3000, maxBytes = 1_000_000) {
  const files: Array<{ path: string; text: string }> = [];
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (files.length >= maxFiles) return;
      if (e.isSymbolicLink() || ["node_modules", ".git", "dist", "build"].includes(e.name)) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (filter(e.name) && fs.statSync(p).size < maxBytes) files.push({ path: path.relative(root, p).split(path.sep).join("/"), text: fs.readFileSync(p, "utf8") });
    }
  };
  walk(root);
  return files;
}

export function launchScan(root: string): { files: number; verdict: string; counts: Record<string, number>; findings: Finding[] } {
  const files = readTree(root, (n) => /\.(sql|ts|tsx|js|jsx|mjs|json|toml|yml|yaml|html)$/.test(n) || /^\.env/.test(n));
  const findings = scanProject(files);
  const counts = { high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const f of findings) counts[f.severity]!++;
  return { files: files.length, verdict: verdict(findings), counts, findings: findings.filter((f) => f.severity !== "low").slice(0, 100) };
}

export function skillScan(root: string) {
  const files = readTree(root, (n) => /\.(md|txt|sh|py|js|ts|json|ya?ml)$/i.test(n) && /(skill|prompt|agent|command|claude|readme|\.sh$|\.py$)/i.test(n) || n === "SKILL.md", 500);
  const results = files.map((f) => scanText(f.path, f.text)).filter((r) => r.findings.length);
  const verdictAll = results.some((r) => r.verdict === "block") ? "block" : results.some((r) => r.verdict === "review") ? "review" : "pass";
  return { files: files.length, verdict: verdictAll, results: results.slice(0, 50) };
}
