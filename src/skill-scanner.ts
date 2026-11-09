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

export function scanText(file: string, text: string): ScanResult {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((ln, i) => {
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
