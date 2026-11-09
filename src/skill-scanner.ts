// skill-scanner: vet a skill, plugin or prompt file BEFORE an agent loads it (clawscan / vibe-shield style).
// Static rules only (no execution). Verdict: "block" if any high finding, "review" if medium, else "pass".
export type Severity = "high" | "medium" | "low";
export interface Finding { rule: string; severity: Severity; line: number; excerpt: string; why: string }
export interface ScanResult { file: string; verdict: "block" | "review" | "pass"; findings: Finding[] }

interface Rule { id: string; severity: Severity; re: RegExp; why: string }
const RULES: Rule[] = [
  { id: "pipe-to-shell", severity: "high", re: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, why: "downloads and runs remote code without review" },
  { id: "decode-and-run", severity: "high", re: /base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh\b|\beval\s*\(\s*(atob|Buffer\.from)\b|exec\(\s*base64/i, why: "hides a payload by encoding it" },
  { id: "destructive-rm", severity: "high", re: /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(\/|~|\$HOME|\*)(\s|$)/i, why: "recursive delete of root, home or everything" },
  { id: "secret-read", severity: "high", re: /(~|\$HOME|\/home\/\w+)\/\.(ssh|aws|gnupg|config\/gcloud)\b|\bcat\s+[^\n]*\.env\b|id_rsa\b/i, why: "reads credentials from well-known locations" },
  { id: "exfil-endpoint", severity: "high", re: /(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|pastebin\.com|transfer\.sh|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)/i, why: "known endpoint used to send data out" },
  { id: "prompt-injection", severity: "high", re: /(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?)|you\s+must\s+not\s+(tell|inform|reveal\s+to)\s+the\s+user|do\s+not\s+(tell|mention\s+this\s+to)\s+the\s+user/i, why: "tries to override the agent's instructions or hide actions from the user" },
  { id: "hidden-unicode", severity: "high", re: /[​-‏‪-‮⁦-⁩\u{E0000}-\u{E007F}]/u, why: "invisible or direction-changing characters can hide instructions" },
  { id: "hardcoded-secret", severity: "high", re: /\b(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk_live_[A-Za-z0-9]{16,})\b|-----BEGIN [A-Z ]*PRIVATE KEY-----/, why: "contains a live-looking credential" },
  { id: "chmod-777", severity: "medium", re: /\bchmod\s+(-R\s+)?0?777\b/, why: "world-writable permissions" },
  { id: "sudo", severity: "medium", re: /(^|[\s;&|])sudo\s/, why: "asks for elevated privileges" },
  { id: "dynamic-exec", severity: "medium", re: /\b(os\.system|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|child_process\.exec\(|new Function\(|\beval\()/, why: "executes strings as code or via a shell" },
  { id: "disable-verification", severity: "medium", re: /(--no-verify|--insecure|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|curl\s+[^\n]*\s-k\b)/, why: "turns off safety or TLS checks" },
  { id: "force-push", severity: "medium", re: /git\s+push\s+[^\n]*(--force\b|-f\b)/, why: "can overwrite shared history" },
  { id: "unpinned-install", severity: "low", re: /\b(npx|pip install|npm i(nstall)?\s+-g)\s+[a-z@][^\s@]*(\s|$)/i, why: "installs an unpinned package" },
];

const POPULAR = ["requests", "numpy", "pandas", "express", "lodash", "react", "axios", "flask", "django", "openai", "anthropic", "boto3", "urllib3", "colorama", "cryptography", "typescript", "webpack", "chalk", "moment", "commander"];
const lev = (a: string, b: string) => { const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)] as number[]); for (let j = 1; j <= b.length; j++) d[0]![j] = j; for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1)); return d[a.length]![b.length]!; };
// A package name one typo away from a famous one is a classic supply-chain trap.
export function typosquat(line: string): string | null {
  const m = /\b(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+add|pip3?\s+install)\s+((?:-{1,2}[\w-]+\s+)*)([A-Za-z0-9_.-]{3,40})/.exec(line);
  const name = m?.[2]?.toLowerCase(); if (!name) return null;
  const hit = POPULAR.find((p) => p !== name && Math.abs(p.length - name.length) <= 1 && lev(p, name) === 1);
  return hit ?? null;
}
const FILE_RULES: Array<{ id: string; severity: Severity; why: string; test: (file: string, text: string) => string | null }> = [
  { id: "nul-obfuscation", severity: "high", why: "NUL bytes hide text from reviewers and simple scanners", test: (_f, t) => (t.includes("\u0000") ? "contains NUL bytes" : null) },
  { id: "bytecode-file", severity: "high", why: "compiled bytecode cannot be reviewed as text", test: (f) => (/\.(pyc|pyo|class|exe|dll|so|dylib)$/i.test(f) ? f : null) },
  { id: "wide-permissions", severity: "medium", why: "asks for every tool or an unrestricted shell", test: (_f, t) => (/allowed-tools:\s*["']?(\*|Bash\(\*\)|Bash)["']?\s*$/im.test(t) ? "allowed-tools grants everything" : null) },
];

export function scanText(file: string, text: string): ScanResult {
  const findings: Finding[] = [];
  for (const r of FILE_RULES) { const hit = r.test(file, text); if (hit) findings.push({ rule: r.id, severity: r.severity, line: 1, excerpt: hit.slice(0, 120), why: r.why }); }
  const lines = text.split(/\r?\n/);
  lines.forEach((ln, i) => {
    const ts = typosquat(ln); if (ts) findings.push({ rule: "typosquat", severity: "high", line: i + 1, excerpt: ln.trim().slice(0, 120), why: `package name is one typo away from "${ts}"` });
    if (/[A-Za-z0-9+/=_-]{240,}/.test(ln)) findings.push({ rule: "encoded-blob", severity: "medium", line: i + 1, excerpt: ln.trim().slice(0, 60) + "...", why: "a very long encoded string can hide a payload" });
    if (/<!--[^>]*\b(assistant|agent|claude|ignore|system prompt|do not tell)\b[^>]*-->/i.test(ln)) findings.push({ rule: "hidden-comment", severity: "medium", line: i + 1, excerpt: ln.trim().slice(0, 120), why: "an HTML comment addressed to the agent is invisible when the file is rendered" });
    for (const r of RULES) {
      if (r.re.test(ln)) findings.push({ rule: r.id, severity: r.severity, line: i + 1, excerpt: ln.replace(/[​-‏‪-‮⁦-⁩]/gu, "�").trim().slice(0, 120), why: r.why });
    }
  });
  const verdict = findings.some((f) => f.severity === "high") ? "block" : findings.some((f) => f.severity === "medium") ? "review" : "pass";
  return { file, verdict, findings };
}

export function scanFiles(files: Array<{ path: string; text: string }>): { verdict: ScanResult["verdict"]; results: ScanResult[] } {
  const results = files.map((f) => scanText(f.path, f.text));
  const verdict = results.some((r) => r.verdict === "block") ? "block" : results.some((r) => r.verdict === "review") ? "review" : "pass";
  return { verdict, results };
}

// One number for a whole skill: each rule counts once per file so repetition does not hide or inflate the picture.
export function scoreScan(results: ScanResult[]): { score: number; recommendation: "install" | "review first" | "do not install"; counts: Record<Severity, number> } {
  const seen = new Set<string>(); const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0 }; let pts = 0;
  for (const r of results) for (const f of r.findings) { const k = `${r.file}|${f.rule}`; if (seen.has(k)) continue; seen.add(k); counts[f.severity]++; pts += f.severity === "high" ? 25 : f.severity === "medium" ? 8 : 2; }
  return { score: Math.max(0, 100 - pts), recommendation: counts.high ? "do not install" : counts.medium ? "review first" : "install", counts };
}
