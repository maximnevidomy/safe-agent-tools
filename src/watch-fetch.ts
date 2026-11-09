// watch-fetch: the "operate politely and notice change" layer around safe-fetch (what API Anything's cache window,
// request budgets and --changes do). A short cache window, a per-site request budget, snapshots with a field-level diff,
// and failures that tell the agent what to do next. Memory only; nothing is written to disk.
import { Deps, SafeFetchError, defaultDeps, safeFetch, type SafeFetchOptions } from "./safe-fetch";

export interface FetchResult { ok: true; url: string; status: number; body: Buffer; headers: Record<string, string | string[] | undefined>; cached: boolean }
export interface FetchFailure { ok: false; error: { class: string; message: string; next: string } }

const NEXT: Record<string, string> = {
  bad_scheme: "Use an https:// link.", bad_url: "Check the link; remove any username or password from it.", bad_port: "Only the standard https port is allowed.",
  blocked_ip: "This address is private or reserved and can never be fetched. Do not retry.", host_not_allowed: "Use a public website name, not an internal one.",
  dns: "The name did not resolve. Check the spelling, then try again later.", timeout: "The site was slow. Retry once later; do not hammer it.",
  too_large: "The page is too big. Ask for a smaller page or a specific file.", too_many_redirects: "The site redirects in a loop. Try its final address.",
  bad_redirect: "The site sent a broken redirect. Try its final address.", budget: "Too many requests to this site. Wait for the window to pass.",
  http_429: "The site asked us to slow down. Wait a few minutes.", http_403: "The site refuses automated visitors. Do not try to bypass it; use its official API or RSS.", http_404: "That page does not exist. Check the link.", http_5xx: "The site has a problem. Retry later.",
};
export const explain = (cls: string, message: string): FetchFailure => ({ ok: false, error: { class: cls, message: message.slice(0, 160), next: NEXT[cls] ?? "Do not retry the same call." } });
export const explainError = (e: unknown): FetchFailure => (e instanceof SafeFetchError ? explain(e.code, e.message) : explain("error", (e as Error)?.message ?? "unknown"));

export class WatchFetch {
  private cache = new Map<string, { at: number; r: FetchResult }>();
  private hits = new Map<string, number[]>();
  private snaps = new Map<string, Record<string, string>>();
  constructor(private o: { cacheMs?: number; perHostPerMin?: number; maxEntries?: number; now?: () => number; deps?: Deps } = {}) {}
  private now() { return (this.o.now ?? Date.now)(); }

  async get(url: string, opts: SafeFetchOptions): Promise<FetchResult | FetchFailure> {
    const key = url; const c = this.cache.get(key);
    if (c && this.now() - c.at < (this.o.cacheMs ?? 60_000)) return { ...c.r, cached: true };
    let host = ""; try { host = new URL(url).host; } catch { return explain("bad_url", "invalid URL"); }
    const recent = (this.hits.get(host) ?? []).filter((t) => t > this.now() - 60_000);
    if (recent.length >= (this.o.perHostPerMin ?? 10)) return explain("budget", `more than ${this.o.perHostPerMin ?? 10} requests per minute to ${host}`);
    this.hits.set(host, [...recent, this.now()]);
    try {
      const r = await safeFetch(url, opts, this.o.deps ?? defaultDeps);
      if (r.status >= 400) return explain(r.status === 429 ? "http_429" : r.status === 403 ? "http_403" : r.status === 404 ? "http_404" : r.status >= 500 ? "http_5xx" : "http_" + r.status, `HTTP ${r.status}`);
      const res: FetchResult = { ok: true, url, status: r.status, body: r.body, headers: r.headers, cached: false };
      this.cache.set(key, { at: this.now(), r: res }); if (this.cache.size > (this.o.maxEntries ?? 200)) this.cache.delete(this.cache.keys().next().value!);
      return res;
    } catch (e) { return explainError(e); }
  }

  // Remember a set of named values for a key (for example price fields of a page) and report what changed since the last call.
  track(key: string, values: Record<string, string>): { first: boolean; changes: Array<{ field: string; before: string | null; after: string | null }> } {
    const before = this.snaps.get(key);
    this.snaps.set(key, values); if (this.snaps.size > (this.o.maxEntries ?? 200)) this.snaps.delete(this.snaps.keys().next().value!);
    if (!before) return { first: true, changes: [] };
    const fields = new Set([...Object.keys(before), ...Object.keys(values)]);
    return { first: false, changes: [...fields].filter((f) => before[f] !== values[f]).map((f) => ({ field: f, before: before[f] ?? null, after: values[f] ?? null })) };
  }
}
