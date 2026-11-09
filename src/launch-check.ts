// launch-check: a pre-launch security check for Supabase/Lovable style projects (check-pre-lancamento idea).
// Static scan of migrations, edge-function config and source. Findings are ranked; "high" should block a release.
export type Severity = "high" | "medium" | "low";
export interface Finding { rule: string; severity: Severity; file: string; line: number; message: string }
export interface SourceFile { path: string; text: string }

const stripSqlComments = (s: string) => s.replace(/--[^\n]*/g, (m) => " ".repeat(m.length)).replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
const lineOf = (text: string, idx: number) => text.slice(0, idx).split("\n").length;
const unq = (s: string) => s.replace(/"/g, "").toLowerCase();

function jwtRole(tok: string): string | null {
  try { return JSON.parse(Buffer.from(tok.split(".")[1]!, "base64url").toString("utf8")).role ?? null; } catch { return null; }
}

export function scanProject(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  const sqlFiles = files.filter((f) => f.path.endsWith(".sql"));
  const sql = sqlFiles.map((f) => ({ f, t: stripSqlComments(f.text) }));

  // 1. tables created without RLS anywhere in the migrations
  const rls = new Set<string>();
  for (const { t } of sql) for (const m of t.matchAll(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:"?\w+"?\.)?"?\w+"?)\s+enable\s+row\s+level\s+security/gi)) rls.add(unq(m[1]!).replace(/^public\./, ""));
  const dropped = new Set<string>();
  for (const { t } of sql) for (const m of t.matchAll(/drop\s+table\s+(?:if\s+exists\s+)?((?:"?\w+"?\.)?"?\w+"?)/gi)) dropped.add(unq(m[1]!).replace(/^public\./, ""));
  const pathFixed = new Set<string>();
  for (const { t } of sql) for (const m of t.matchAll(/alter\s+function\s+((?:"?\w+"?\.)?"?\w+"?)\s*\([^)]*\)\s+set\s+search_path/gi)) pathFixed.add(unq(m[1]!).replace(/^public\./, ""));
  for (const { f, t } of sql) {
    for (const m of t.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?((?:"?\w+"?\.)?"?\w+"?)/gi)) {
      const name = unq(m[1]!);
      if (name.includes(".") && !name.startsWith("public.")) continue; // other schemas are not exposed by default
      const bare = name.replace(/^public\./, "");
      if (!rls.has(bare) && !dropped.has(bare)) out.push({ rule: "rls-missing", severity: "high", file: f.path, line: lineOf(t, m.index!), message: `table ${bare} is created without ENABLE ROW LEVEL SECURITY` });
    }
    // 2. grants of write access to anon
    for (const m of t.matchAll(/grant\s+([^;]*?)\s+on\s+[^;]*?\s+to\s+([^;]*)/gi)) {
      const privs = m[1]!.toLowerCase(), to = m[2]!.toLowerCase();
      if (!/\banon\b/.test(to)) continue;
      if (/(update|delete|truncate|\ball\b)/.test(privs)) out.push({ rule: "anon-write-grant", severity: "high", file: f.path, line: lineOf(t, m.index!), message: "anon can change or delete rows" });
      else if (/insert/.test(privs)) out.push({ rule: "public-insert", severity: "low", file: f.path, line: lineOf(t, m.index!), message: "anon can insert (public form): confirm size limits and rate limiting" });
    }
    // 3. wide-open policies
    for (const m of t.matchAll(/create\s+policy[\s\S]*?;/gi)) {
      const p = m[0].toLowerCase();
      const cmd = /for\s+(all|select|insert|update|delete)/.exec(p)?.[1] ?? "all";
      const open = /(using|with\s+check)\s*\(\s*true\s*\)/.test(p);
      const toClients = /\bto\s+[^;]*\b(anon|public)\b/.test(p) || !/\bto\s+/.test(p);
      if (!open || !toClients || cmd === "select") continue;
      if (cmd === "insert") out.push({ rule: "public-insert", severity: "low", file: f.path, line: lineOf(t, m.index!), message: "anyone can insert (public form): confirm size limits and rate limiting" });
      else out.push({ rule: "policy-open-write", severity: "high", file: f.path, line: lineOf(t, m.index!), message: `policy lets everyone ${cmd} rows (using/with check true)` });
    }
    // 4. SECURITY DEFINER without a fixed search_path
    for (const m of t.matchAll(/create\s+(?:or\s+replace\s+)?function[\s\S]*?(?:\$\$|\$function\$|\$body\$)[\s\S]*?(?:\$\$|\$function\$|\$body\$)/gi)) {
      const fn = m[0].toLowerCase();
      const name = unq(/function\s+((?:"?\w+"?\.)?"?\w+"?)/i.exec(m[0])?.[1] ?? "").replace(/^public\./, "");
      if (/security\s+definer/.test(fn) && !/set\s+search_path/.test(fn) && !pathFixed.has(name)) out.push({ rule: "definer-search-path", severity: "medium", file: f.path, line: lineOf(t, m.index!), message: "SECURITY DEFINER function without SET search_path" });
    }
  }

  for (const f of files) {
    const base = f.path.split("/").pop() ?? "";
    // 5. committed env files
    if (/^\.env(\..+)?$/.test(base) && !/\.(example|sample|template)$/.test(base)) {
      const privateVars = f.text.split("\n").map((l) => /^\s*([A-Z0-9_]+)\s*=\s*\S+/.exec(l)?.[1]).filter((k): k is string => !!k && !/^(VITE|NEXT_PUBLIC|PUBLIC|REACT_APP|EXPO_PUBLIC)_/.test(k));
      if (privateVars.length) out.push({ rule: "env-committed", severity: "high", file: f.path, line: 1, message: `environment file is committed and holds non-public variables (${privateVars.slice(0, 3).join(", ")})` });
      else out.push({ rule: "env-public-only", severity: "low", file: f.path, line: 1, message: "environment file is committed but only has public-prefixed variables" });
    }
    // 6. edge functions without JWT verification (need an in-code auth check)
    if (f.path.endsWith("config.toml")) for (const m of f.text.matchAll(/\[functions\.([\w-]+)\]\s*\n(?:[^\[]*\n)*?\s*verify_jwt\s*=\s*false/g)) out.push({ rule: "verify-jwt-off", severity: "low", file: f.path, line: lineOf(f.text, m.index!), message: `function ${m[1]} has verify_jwt=false: confirm it authenticates inside the code` });
    if (/\.(ts|tsx|js|jsx|mjs|json|toml|yml|yaml|html)$/.test(f.path)) {
      // 7. service-role key or live secrets in source
      for (const m of f.text.matchAll(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g)) if (jwtRole(m[0]) === "service_role") out.push({ rule: "service-role-key", severity: "high", file: f.path, line: lineOf(f.text, m.index!), message: "a service_role JWT is present in source" });
      for (const m of f.text.matchAll(/\b(sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/g)) out.push({ rule: "secret-in-source", severity: "high", file: f.path, line: lineOf(f.text, m.index!), message: "live-looking secret in source" });
      // 8. risky browser sinks
      if (/\.(tsx|jsx|js|ts|html)$/.test(f.path)) for (const m of f.text.matchAll(/dangerouslySetInnerHTML|\beval\s*\(|document\.write\s*\(/g)) out.push({ rule: "xss-sink", severity: "low", file: f.path, line: lineOf(f.text, m.index!), message: `${m[0]} found: confirm the input is sanitised` });
    }
  }
  const rank = { high: 0, medium: 1, low: 2 } as const;
  return out.sort((a, b) => rank[a.severity] - rank[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
}

export const verdict = (f: Finding[]) => (f.some((x) => x.severity === "high") ? "block" : f.some((x) => x.severity === "medium") ? "review" : "pass");
