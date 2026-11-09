// read-page: turn any public web page into clean text for an agent (the "web reader" channel of Agent-Reach, done safely).
// Public https only through safe-fetch (SSRF-safe, size capped). Output is plain text plus https links; scripts, styles and markup are dropped.
import { Deps, defaultDeps, safeFetch } from "./safe-fetch";

export interface PageText { title: string; text: string; links: Array<{ text: string; url: string }>; chars: number; truncated: boolean }

const ENT: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
const unent = (s: string) => s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e: string) => {
  if (e[0] === "#") { const n = e[1]?.toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 31 && n < 0x10ffff ? String.fromCodePoint(n) : " "; }
  return ENT[e.toLowerCase()] ?? m;
});

export function htmlToText(html: string, pageUrl: string, maxChars = 6000): PageText {
  const title = unent((/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1] ?? "").replace(/<[^>]*>/g, "")).replace(/\s+/g, " ").trim().slice(0, 200);
  const body = html.replace(/<!--[\s\S]*?-->/g, " ").replace(/<(script|style|noscript|svg|template|iframe|nav|footer|header|form)[\s\S]*?<\/\1>/gi, " ");
  const links: PageText["links"] = []; const seen = new Set<string>();
  for (const m of body.matchAll(/<a\s[^>]*href=["']([^"'#][^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    let u: URL; try { u = new URL(unent(m[1]!), pageUrl); } catch { continue; }
    if (u.protocol !== "https:" || u.username || u.password || seen.has(u.href)) continue;
    const t = unent(m[2]!.replace(/<[^>]*>/g, "")).replace(/\s+/g, " ").trim().slice(0, 100);
    if (!t) continue; seen.add(u.href); if (links.length < 20) links.push({ text: t, url: u.href });
  }
  const text = unent(body.replace(/<(br|\/p|\/div|\/li|\/h[1-6]|\/tr)[^>]*>/gi, "\n").replace(/<[^>]*>/g, " ")).replace(/[ \t\f\v ]+/g, " ").replace(/\s*\n\s*/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  return { title, text: text.slice(0, maxChars), links, chars: text.length, truncated: text.length > maxChars };
}

export async function readPage(url: string, deps: Deps = defaultDeps): Promise<PageText & { finalUrl: string }> {
  const r = await safeFetch(url, { allowHosts: [], allowAnyPublic: true, maxBytes: 1_500_000, timeoutMs: 10_000, headers: { Accept: "text/html,text/plain;q=0.9", "User-Agent": "safe-agent-tools/1.0" } }, deps);
  if (r.status !== 200) throw new Error(`page HTTP ${r.status}`);
  const ct = String(r.headers["content-type"] ?? "");
  if (!/text\/(html|plain)|application\/xhtml/i.test(ct)) throw new Error(`not a text page (${ct.split(";")[0] || "unknown type"})`);
  return { ...htmlToText(r.body.toString("utf8"), url), finalUrl: url };
}
