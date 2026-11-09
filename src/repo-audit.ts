// repo-audit: static safety review of a repository's files. Pure functions (no network, nothing is executed).
// Picks the files that matter most (install hooks, scripts, workflows, source), scans them with the skill-scanner
// rules plus install-hook and committed-secret checks, and turns the findings into score deductions.
import { scanText, type Severity } from "./skill-scanner";

export interface TreeEntry { path: string; type: string; size?: number }
export interface AuditFinding { file: string; line: number; severity: Severity; rule: string; why: string; excerpt: string }

const SKIP_DIRS = /(^|\/)(node_modules|dist|build|vendor|\.git|\.next|coverage|__pycache__|\.venv|venv|target)(\/|$)/i;
const CODE_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|py|sh|bash|ps1|yml|yaml|toml|sql)$/i;
const NAMED = /(^|\/)(package\.json|setup\.py|pyproject\.toml|Dockerfile|Makefile|install[^/]*|Gemfile)$/i;
const SECRET_PATH = /(^|\/)(\.env(\.(?!example$|sample$|template$)[^/]+)?|id_(rsa|ed25519|ecdsa)|[^/]+\.(pem|p12|pfx)|credentials(\.json)?|\.netrc)$/i;
export const LIMITS = { maxFiles: 40, maxFileBytes: 100_000, maxTotalBytes: 600_000 };

export function secretFilePaths(tree: TreeEntry[]): string[] {
  return tree.filter((t) => t.type === "blob" && SECRET_PATH.test(t.path)).map((t) => t.path).slice(0, 20);
}

// Highest-risk places first: manifests and install scripts, CI workflows, shell scripts, then shallow, small source files.
export function pickFiles(tree: TreeEntry[]): { picked: string[]; candidates: number; skippedLarge: number } {
  const cands = tree.filter((t) => t.type === "blob" && !SKIP_DIRS.test(t.path) && (NAMED.test(t.path) || CODE_EXT.test(t.path)) && !/\.min\.js$/i.test(t.path));
  let skippedLarge = 0;
  const ok = cands.filter((t) => { if ((t.size ?? 0) > LIMITS.maxFileBytes) { skippedLarge++; return false; } return true; });
  const rank = (t: TreeEntry) => (NAMED.test(t.path) ? 0 : /^\.github\/workflows\//.test(t.path) ? 1 : /\.(sh|bash|ps1)$/i.test(t.path) ? 2 : 3) * 1000 + t.path.split("/").length * 10;
  ok.sort((a, b) => rank(a) - rank(b) || (a.size ?? 0) - (b.size ?? 0));
  const picked: string[] = []; let total = 0;
  for (const t of ok) { if (picked.length >= LIMITS.maxFiles || total + (t.size ?? 0) > LIMITS.maxTotalBytes) continue; picked.push(t.path); total += t.size ?? 0; }
  return { picked, candidates: cands.length, skippedLarge };
}

const REMOTE_HOOK = /(curl|wget|node\s+-e|powershell|\|\s*(ba|z)?sh\b|\beval\b|base64)/i;
export function auditFiles(files: Array<{ path: string; text: string }>): AuditFinding[] {
  const out: AuditFinding[] = [];
  for (const f of files) {
    for (const x of scanText(f.path, f.text).findings) out.push({ file: f.path, line: x.line, severity: x.severity, rule: x.rule, why: x.why, excerpt: x.excerpt });
    if (/(^|\/)package\.json$/i.test(f.path)) {
      let scripts: Record<string, unknown> = {};
      try { scripts = (JSON.parse(f.text) as { scripts?: Record<string, unknown> }).scripts ?? {}; } catch { /* not valid JSON */ }
      for (const hook of ["preinstall", "install", "postinstall"]) {
        const cmd = scripts[hook]; if (typeof cmd !== "string") continue;
        const line = Math.max(1, f.text.split(/\r?\n/).findIndex((l) => l.includes(`"${hook}"`)) + 1);
        out.push({ file: f.path, line, severity: REMOTE_HOOK.test(cmd) ? "high" : "medium", rule: REMOTE_HOOK.test(cmd) ? "install-hook-remote" : "install-hook", why: REMOTE_HOOK.test(cmd) ? "runs a download, encoded or inline script automatically when installed" : "runs code automatically on install", excerpt: `${hook}: ${cmd}`.slice(0, 120) });
      }
    }
  }
  return out;
}

// Points lost for code findings. Each rule counts once per file; the total is capped so one noisy file cannot zero the score.
export const POINTS: Record<Severity, number> = { high: -15, medium: -5, low: -1 };
export function codePoints(findings: AuditFinding[], secretFiles: string[]): number {
  const seen = new Set<string>(); let pts = 0;
  for (const f of findings) { const k = `${f.rule}|${f.file}`; if (seen.has(k)) continue; seen.add(k); pts += POINTS[f.severity]; }
  pts += secretFiles.length * -15;
  return Math.max(-60, pts);
}
