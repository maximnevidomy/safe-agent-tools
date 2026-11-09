// local-index: a local full-text search for agents ("xerj" style) that never touches the network and cannot
// be tricked into reading outside its root or indexing secrets. Defences: root confinement via realpath,
// symlinks skipped, secret-looking files and folders skipped, size/file-count caps, binary files skipped,
// snippets are redacted before they are returned. BM25-lite ranking.
import fs from "node:fs";
import path from "node:path";
import { redact } from "./llm-router";

const SKIP_DIRS = new Set([".git", "node_modules", ".ssh", ".aws", ".gnupg", "dist", "build"]);
const SECRET_FILE = /(^\.env(\..*)?$)|(\.pem$)|(\.key$)|(^id_(rsa|ed25519|ecdsa))|(^credentials(\.json)?$)|(\.p12$)|(\.pfx$)|(^\.npmrc$)|(^\.netrc$)/i;
const TEXT_EXT = new Set([".md", ".txt", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".json", ".sql", ".yml", ".yaml", ".toml", ".py", ".go", ".rs", ".java", ".rb", ".php", ".sh", ".html", ".css", ".csv"]);
const ENV_EXAMPLE = /^\.env\.(example|sample|template)$/i;

export interface IndexOptions { maxFileBytes?: number; maxFiles?: number }
interface Doc { rel: string; text: string; tokens: Map<string, number>; len: number }
// Splits camelCase and snake_case so "getUserName" is found by "user" or "name", and keeps the whole word too.
const tok = (s: string) => {
  const out: string[] = [];
  for (const w of s.match(/[\p{L}\p{N}_]{2,}/gu) ?? []) {
    out.push(w.toLowerCase());
    const parts = w.replace(/([\p{Ll}\d])(\p{Lu})/gu, "$1 $2").replace(/(\p{Lu}+)(\p{Lu}\p{Ll})/gu, "$1 $2").split(/[_\s]+/).filter((x) => x.length >= 2);
    if (parts.length > 1) for (const x of parts) out.push(x.toLowerCase());
  }
  return out;
};

export class LocalIndex {
  private docs: Doc[] = [];
  private df = new Map<string, number>();
  skipped: Array<{ rel: string; reason: string }> = [];
  private constructor(readonly root: string) {}

  static build(root: string, o: IndexOptions = {}): LocalIndex {
    const real = fs.realpathSync(root);
    const idx = new LocalIndex(real);
    const maxBytes = o.maxFileBytes ?? 256_000, maxFiles = o.maxFiles ?? 5000;
    const walk = (dir: string) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (idx.docs.length >= maxFiles) return;
        const abs = path.join(dir, ent.name);
        const rel = path.relative(real, abs);
        if (ent.isSymbolicLink()) { idx.skipped.push({ rel, reason: "symlink" }); continue; }
        if (ent.isDirectory()) { if (SKIP_DIRS.has(ent.name)) idx.skipped.push({ rel, reason: "skipped_dir" }); else walk(abs); continue; }
        if (!ent.isFile()) continue;
        if (SECRET_FILE.test(ent.name) && !ENV_EXAMPLE.test(ent.name)) { idx.skipped.push({ rel, reason: "secret_file" }); continue; }
        if (!TEXT_EXT.has(path.extname(ent.name).toLowerCase()) && !ENV_EXAMPLE.test(ent.name)) { idx.skipped.push({ rel, reason: "extension" }); continue; }
        const st = fs.statSync(abs);
        if (st.size > maxBytes) { idx.skipped.push({ rel, reason: "too_large" }); continue; }
        const buf = fs.readFileSync(abs);
        if (buf.includes(0)) { idx.skipped.push({ rel, reason: "binary" }); continue; }
        idx.add(rel, buf.toString("utf8"));
      }
    };
    walk(real);
    return idx;
  }

  private add(rel: string, text: string) {
    const tokens = new Map<string, number>();
    const all = tok(text);
    for (const t of all) tokens.set(t, (tokens.get(t) ?? 0) + 1);
    for (const t of tokens.keys()) this.df.set(t, (this.df.get(t) ?? 0) + 1);
    this.docs.push({ rel, text, tokens, len: all.length });
  }

  get size() { return this.docs.length; }

  search(query: string, k = 5): Array<{ path: string; line: number; score: number; snippet: string }> {
    const q = [...new Set(tok(query))];
    if (!q.length) return [];
    const N = this.docs.length, avg = this.docs.reduce((a, d) => a + d.len, 0) / Math.max(N, 1);
    const scored = this.docs.map((d) => {
      let s = 0;
      for (const t of q) {
        const f = d.tokens.get(t) ?? 0;
        if (!f) continue;
        const idf = Math.log(1 + (N - (this.df.get(t) ?? 0) + 0.5) / ((this.df.get(t) ?? 0) + 0.5));
        s += idf * ((f * 2.2) / (f + 1.2 * (0.25 + 0.75 * (d.len / avg))));
      }
      return { d, s };
    }).filter((x) => x.s > 0).sort((a, b) => b.s - a.s).slice(0, Math.min(k, 20));
    return scored.map(({ d, s }) => {
      const at = Math.max(0, d.text.toLowerCase().indexOf(q.find((t) => d.text.toLowerCase().includes(t)) ?? ""));
      return { path: d.rel, line: d.text.slice(0, at).split("\n").length, score: +s.toFixed(3), snippet: redact(d.text.slice(Math.max(0, at - 60), at + 140).replace(/\s+/g, " ")).text };
    });
  }

  // Read a file by relative path, confined to the root. Rejects traversal, absolute paths and symlinks.
  readFile(rel: string): string {
    if (typeof rel !== "string" || rel.includes("\0") || path.isAbsolute(rel)) throw new Error("path not allowed");
    const abs = path.resolve(this.root, rel);
    if (abs !== this.root && !abs.startsWith(this.root + path.sep)) throw new Error("path escapes root");
    if (!this.docs.some((d) => d.rel === path.relative(this.root, abs))) throw new Error("file is not in the index");
    if (fs.lstatSync(abs).isSymbolicLink()) throw new Error("symlinks are not readable");
    return redact(fs.readFileSync(abs, "utf8")).text;
  }

  // Go-to-definition: where is this function, class, type or constant defined? Returns file, line and the declaration line (redacted).
  def(symbol: string, k = 10): Array<{ path: string; line: number; kind: string; text: string }> {
    if (!/^[A-Za-z_$][\w$]{0,80}$/.test(symbol)) return [];
    const e = symbol.replace(/\$/g, "\\$");
    const re = new RegExp(`^\\s*(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?(?:(function\\*?|class|interface|type|enum|const|let|var|def|fn|func|struct|trait|impl)\\s+${e}\\b|(public|private|protected|static)[\\w\\s<>\\[\\],]*\\s${e}\\s*\\()`);
    const out: Array<{ path: string; line: number; kind: string; text: string }> = [];
    for (const d of this.docs) {
      const lines = d.text.split("\n");
      for (let i = 0; i < lines.length && out.length < k; i++) { const m = re.exec(lines[i]!); if (m) out.push({ path: d.rel, line: i + 1, kind: m[1] ?? "method", text: redact(lines[i]!.trim().slice(0, 160)).text }); }
    }
    return out;
  }
}
