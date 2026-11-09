// site-check: read-only pre-launch audit of a LIVE public website (the "scan a given URL" half of check-pre-lancamento).
// GET requests only, public https only, via safe-fetch. It looks at response headers, a few well-known leak paths, the page's
// own scripts for leaked keys and source maps, and basic launch-readiness (SEO, legal pages, mobile). Nothing is changed or attacked.
import { Deps, defaultDeps, safeFetch } from "./safe-fetch";
import { scanText } from "./skill-scanner";

export type Sev = "high" | "medium" | "low";
export interface SiteFinding { area: "security" | "readiness"; severity: Sev; rule: string; message: string }
export interface SiteReport { url: string; security: number; readiness: number; verdict: "launch" | "fix-first" | "do-not-launch"; findings: SiteFinding[]; checked: string[] }

const PTS: Record<Sev, number> = { high: -25, medium: -10, low: -4 };
const score = (f: SiteFinding[], area: SiteFinding["area"]) => Math.max(0, 100 + f.filter((x) => x.area === area).reduce((a, x) => a + PTS[x.severity], 0));

async function get(url: string, deps: Deps, maxBytes = 400_000) {
  try { return await safeFetch(url, { allowHosts: [], allowAnyPublic: true, maxBytes, timeoutMs: 6000, headers: { "User-Agent": "safe-agent-tools-sitecheck/1.0", Accept: "*/*" } }, deps); } catch { return null; }
}
const hv = (h: Record<string, string | string[] | undefined>, k: string) => { const v = h[k]; return Array.isArray(v) ? v.join(", ") : v ?? ""; };
const looksHtml = (b: Buffer) => /<\s*(html|!doctype|head|body|script|div)\b/i.test(b.subarray(0, 600).toString("utf8"));

// A Supabase/JWT-style token whose payload says role=service_role gives full database access to whoever reads it.
export function serviceRoleTokens(text: string): number {
  let n = 0;
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}/g)) {
    try { if ((JSON.parse(Buffer.from(m[1]!, "base64url").toString("utf8")) as { role?: string }).role === "service_role") n++; } catch { /* not a JWT */ }
  }
  return n;
}

export async function checkSite(rawUrl: string, deps: Deps = defaultDeps): Promise<SiteReport> {
  const u = new URL(rawUrl); const origin = u.origin; const f: SiteFinding[] = []; const checked: string[] = [];
  const add = (area: SiteFinding["area"], severity: Sev, rule: string, message: string) => f.push({ area, severity, rule, message });
  const home = await safeFetch(rawUrl, { allowHosts: [], allowAnyPublic: true, maxBytes: 1_000_000, timeoutMs: 8000, headers: { "User-Agent": "safe-agent-tools-sitecheck/1.0", Accept: "text/html,*/*" } }, deps);
  if (home.status >= 400) throw new Error(`site HTTP ${home.status}`);
  const h = home.headers; const html = home.body.toString("utf8"); checked.push("home page", "response headers");

  // Security headers
  if (!hv(h, "strict-transport-security")) add("security", "medium", "no-hsts", "No Strict-Transport-Security header: browsers may be tricked onto plain http.");
  const csp = hv(h, "content-security-policy");
  if (!csp) add("security", "medium", "no-csp", "No Content-Security-Policy: an injected script would run freely.");
  else if (/script-src[^;]*'unsafe-inline'|default-src[^;]*'unsafe-inline'/.test(csp)) add("security", "low", "weak-csp", "CSP allows 'unsafe-inline' scripts.");
  if (!/nosniff/i.test(hv(h, "x-content-type-options"))) add("security", "low", "no-nosniff", "Missing X-Content-Type-Options: nosniff.");
  if (!hv(h, "x-frame-options") && !/frame-ancestors/i.test(csp)) add("security", "medium", "clickjacking", "Page can be framed by any site (no X-Frame-Options or frame-ancestors).");
  if (!hv(h, "referrer-policy")) add("security", "low", "no-referrer-policy", "No Referrer-Policy header.");
  if (/\d/.test(hv(h, "x-powered-by")) || /\/\d/.test(hv(h, "server"))) add("security", "low", "version-leak", `Server announces its software/version (${(hv(h, "x-powered-by") || hv(h, "server")).slice(0, 40)}).`);
  if (hv(h, "access-control-allow-origin") === "*") add("security", /true/i.test(hv(h, "access-control-allow-credentials")) ? "high" : "low", "open-cors", "CORS allows every origin (*).");
  const cookies = Array.isArray(h["set-cookie"]) ? h["set-cookie"] : h["set-cookie"] ? [h["set-cookie"]] : [];
  for (const c of cookies) { const name = c.split("=")[0]!.slice(0, 30); const miss = [!/;\s*secure/i.test(c) && "Secure", !/;\s*httponly/i.test(c) && "HttpOnly", !/;\s*samesite/i.test(c) && "SameSite"].filter(Boolean); if (miss.length) add("security", /session|auth|token|sid/i.test(name) ? "medium" : "low", "cookie-flags", `Cookie "${name}" lacks ${miss.join(", ")}.`); }

  // Well-known leaks (a single-page app often answers 200 with HTML for any path, so the content must look right)
  const probes = await Promise.all([get(`${origin}/.env`, deps, 20_000), get(`${origin}/.git/config`, deps, 20_000), get(`${origin}/robots.txt`, deps, 50_000), get(`${origin}/sitemap.xml`, deps, 50_000), get(`${origin}/__nope_${Date.now() % 100000}`, deps, 20_000)]);
  checked.push("/.env", "/.git/config", "robots.txt", "sitemap.xml", "404 page");
  const [env, git, robots, sitemap, nf] = probes;
  if (env?.status === 200 && !looksHtml(env.body) && /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(env.body.toString("utf8"))) add("security", "high", "exposed-env", "/.env is publicly downloadable and contains settings.");
  if (git?.status === 200 && /\[core\]/.test(git.body.toString("utf8"))) add("security", "high", "exposed-git", "/.git/config is publicly readable: the source code may be downloadable.");

  // The page's own scripts: leaked keys and public source maps
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => { try { return new URL(m[1]!, rawUrl); } catch { return null; } }).filter((x): x is URL => !!x && x.protocol === "https:").slice(0, 3);
  const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]!).join("\n");
  const bodies = await Promise.all(scripts.map((s) => get(s.href, deps, 1_500_000)));
  checked.push(`${scripts.length} script file(s)`);
  let mapChecked = false;
  for (const [i, b] of bodies.entries()) {
    const text = b?.status === 200 ? b.body.toString("utf8") : ""; if (!text) continue;
    if (serviceRoleTokens(text) > 0) add("security", "high", "service-role-key", `A Supabase service_role key is inside ${scripts[i]!.pathname}: anyone can read and change the whole database.`);
    if (scanText(scripts[i]!.pathname, text.slice(0, 1_200_000)).findings.some((x) => x.rule === "hardcoded-secret")) add("security", "high", "secret-in-bundle", `A live-looking secret key appears in ${scripts[i]!.pathname}.`);
    if (!mapChecked) { const ref = /\/\/[#@]\s*sourceMappingURL=(\S+)/.exec(text.slice(-600))?.[1]; if (ref && !ref.startsWith("data:")) { mapChecked = true; const mapUrl = new URL(ref, scripts[i]!.href); const mp = mapUrl.protocol === "https:" ? await get(mapUrl.href, deps, 300_000) : null; if (mp?.status === 200 && /"sources"/.test(mp.body.toString("utf8").slice(0, 2000))) add("security", "medium", "source-map", "Source maps are public: your original source code can be read in the browser."); } }
  }
  if (serviceRoleTokens(inline) > 0) add("security", "high", "service-role-key", "A Supabase service_role key is inside an inline script.");

  // Launch readiness
  if (!/<title[^>]*>\s*\S/i.test(html)) add("readiness", "medium", "no-title", "The page has no title.");
  if (!/<meta[^>]+name=["']description["'][^>]+content=["'][^"']{20,}/i.test(html)) add("readiness", "medium", "no-description", "No meta description: search results and link previews will look poor.");
  if (!/property=["']og:(title|image)["']/i.test(html)) add("readiness", "low", "no-og", "No Open Graph tags: shared links show no preview card.");
  if (!/name=["']viewport["']/i.test(html)) add("readiness", "medium", "no-viewport", "No viewport meta tag: the page will look broken on phones.");
  if (!/<html[^>]+\blang=/i.test(html)) add("readiness", "low", "no-lang", "The <html> tag has no lang attribute.");
  if (!/rel=["'](shortcut )?icon["']/i.test(html)) add("readiness", "low", "no-favicon", "No favicon link.");
  if (!/(privacy|terms|תקנון|פרטיות|מדיניות)/i.test(html)) add("readiness", "medium", "no-legal", "No privacy policy or terms link found on the home page.");
  if (!(robots?.status === 200 && !looksHtml(robots.body))) add("readiness", "low", "no-robots", "No robots.txt.");
  if (!(sitemap?.status === 200 && /<(urlset|sitemapindex)/i.test(sitemap.body.toString("utf8")))) add("readiness", "low", "no-sitemap", "No sitemap.xml.");
  if (nf && nf.status === 200 && looksHtml(nf.body)) add("readiness", "low", "soft-404", "Unknown addresses return 200 instead of 404 (normal for single-page apps, but search engines may index junk).");

  const security = score(f, "security"), readiness = score(f, "readiness");
  const verdict = f.some((x) => x.severity === "high") ? "do-not-launch" : f.some((x) => x.severity === "medium") ? "fix-first" : "launch";
  return { url: rawUrl, security, readiness, verdict, findings: f, checked };
}
