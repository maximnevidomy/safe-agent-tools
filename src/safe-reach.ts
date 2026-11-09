// safe-reach: read-only access to public sources through LEGAL channels only (official GitHub API, RSS/Atom).
// No browser cookies, no account sessions, no shell installers. Everything goes through safe-fetch.
import { Deps, defaultDeps, safeFetch } from "./safe-fetch";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

export async function githubRepo(owner: string, repo: string, opts: { token?: string } = {}, deps: Deps = defaultDeps) {
  if (!OWNER.test(owner) || !REPO.test(repo) || repo === "." || repo === "..") throw new Error("invalid owner/repo");
  const headers: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "safe-agent-tools" };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const r = await safeFetch(`https://api.github.com/repos/${owner}/${repo}`, { allowHosts: ["api.github.com"], maxBytes: 500_000, headers }, deps);
  if (r.status !== 200) throw new Error(`GitHub HTTP ${r.status}`);
  const j = JSON.parse(r.body.toString("utf8"));
  // Return only the fields we need, never the raw payload.
  return {
    full_name: String(j.full_name), stars: Number(j.stargazers_count), license: j.license?.spdx_id ?? null,
    pushed_at: String(j.pushed_at), archived: Boolean(j.archived), default_branch: String(j.default_branch),
  };
}

const decode = (s: string) =>
  s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&amp;/g, "&").trim();
const tag = (block: string, name: string) => {
  const m = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "i").exec(block);
  return m ? decode(m[1]!) : "";
};

export interface FeedItem { title: string; link: string; date: string }

// Output is plain text only: titles are stripped of markup, links must be https.
export async function readFeed(url: string, allowHosts: string[], deps: Deps = defaultDeps): Promise<FeedItem[]> {
  const r = await safeFetch(url, { allowHosts, maxBytes: 1_000_000 }, deps);
  if (r.status !== 200) throw new Error(`feed HTTP ${r.status}`);
  const xml = r.body.toString("utf8");
  const blocks = xml.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) ?? [];
  return blocks.slice(0, 50).map((b) => {
    const href = /<link[^>]*href="([^"]+)"/i.exec(b)?.[1] ?? tag(b, "link");
    const link = /^https:\/\//i.test(href) ? href : "";
    return {
      title: tag(b, "title").replace(/<[^>]*>/g, "").slice(0, 300),
      link,
      date: tag(b, "pubDate") || tag(b, "updated") || tag(b, "published"),
    };
  });
}

// README as plain text from the official API (raw media type). Capped, never executed or rendered.
export async function githubReadme(owner: string, repo: string, opts: { token?: string } = {}, deps: Deps = defaultDeps): Promise<string> {
  if (!OWNER.test(owner) || !REPO.test(repo) || repo === "." || repo === "..") throw new Error("invalid owner/repo");
  const headers: Record<string, string> = { Accept: "application/vnd.github.raw+json", "User-Agent": "safe-agent-tools" };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const r = await safeFetch(`https://api.github.com/repos/${owner}/${repo}/readme`, { allowHosts: ["api.github.com"], maxBytes: 300_000, headers }, deps);
  if (r.status === 404) return "";
  if (r.status !== 200) throw new Error(`GitHub HTTP ${r.status}`);
  return r.body.toString("utf8");
}

// Turn the signals we care about (license, activity, archive state, README content) into one verdict and a 0-100 score.
// Score starts at 100 and loses points per signal, so every point is explained. A "bad" signal always means reject.
export function vetRepo(meta: { stars: number; license: string | null; pushed_at: string; archived: boolean }, readmeFindings: Array<{ severity: string; rule: string }>, now = Date.now()) {
  const signals: Array<{ level: "bad" | "warn" | "ok"; text: string; points: number }> = [];
  const days = Math.floor((now - Date.parse(meta.pushed_at)) / 86_400_000);
  if (meta.archived) signals.push({ level: "bad", text: "repository is archived", points: -40 });
  if (!meta.license || meta.license === "NOASSERTION") signals.push({ level: "bad", text: "no clear license", points: -25 }); else signals.push({ level: "ok", text: `license ${meta.license}`, points: 0 });
  if (Number.isFinite(days)) signals.push({ level: days > 180 ? "bad" : days > 90 ? "warn" : "ok", text: `last push ${days} days ago`, points: days > 180 ? -25 : days > 90 ? -10 : 0 });
  if (meta.stars < 20) signals.push({ level: "warn", text: `only ${meta.stars} stars (young or unproven)`, points: -10 });
  for (const f of readmeFindings.filter((x) => x.severity === "high")) signals.push({ level: "bad", text: `README risk: ${f.rule}`, points: -30 });
  const score = Math.max(0, 100 + signals.reduce((a, x) => a + x.points, 0));
  const verdict = signals.some((x) => x.level === "bad") ? "reject" : signals.some((x) => x.level === "warn") ? "review" : "ok";
  return { verdict, score, signals };
}
