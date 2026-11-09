// llm-router: failover across LLM providers without leaking sensitive data to untrusted free tiers.
// Rules: every provider declares the most sensitive data it may receive; a request declares how sensitive
// it is; a provider is only used when it is allowed to see that level. Redaction runs before anything
// leaves for a provider below "secret" level. Logs hold metadata only, never prompt or answer text.

export type Sensitivity = "public" | "internal" | "secret";
const RANK: Record<Sensitivity, number> = { public: 0, internal: 1, secret: 2 };

export interface Provider {
  id: string;
  maxSensitivity: Sensitivity; // free/unknown providers: "public". Our own approved ones: "internal". Local model: "secret".
  call(prompt: string, signal: AbortSignal): Promise<string>;
  rpm?: number; // optional ceiling: requests per minute this provider's free tier allows; the router stays under it
}
// Throw this from a provider on HTTP 429 so the router rests that provider for the time it asked for.
export class RateLimitedError extends Error {
  constructor(public retryAfterMs = 30_000) { super("rate limited"); this.name = "RateLimitedError"; }
}
export interface LogEntry {
  provider: string;
  ok: boolean;
  ms: number;
  promptChars: number;
  redactions: number;
  error?: string; // error class only
}
export interface RouterOptions {
  providers: Provider[];
  timeoutMs?: number;
  failuresBeforeOpen?: number;
  cooldownMs?: number;
  strategy?: "order" | "fast" | "reliable"; // order = list order; fast/reliable = rank by what the router has observed
  stickyMs?: number; // keep a conversation on the same provider for this long (default 30 min)
  cacheMs?: number; // opt-in: reuse an identical answer for this long. Never used for "secret" data.
  log?: (e: LogEntry) => void;
  now?: () => number;
}

const luhn = (digits: string) => {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
};

export function redact(text: string): { text: string; count: number } {
  let count = 0;
  const sub = (re: RegExp, label: string, guard?: (m: string) => boolean) => {
    text = text.replace(re, (m) => {
      if (guard && !guard(m)) return m;
      count++;
      return `[${label}]`;
    });
  };
  sub(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "PRIVATE_KEY");
  sub(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "JWT");
  sub(/\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g, "API_KEY");
  sub(/\bsk-ant-[A-Za-z0-9_-]{16,}\b/g, "API_KEY");
  sub(/\bAKIA[0-9A-Z]{16}\b/g, "AWS_KEY");
  sub(/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, "GITHUB_TOKEN");
  sub(/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, "BEARER");
  sub(/\b(?:\d[ -]?){13,19}\b/g, "CARD", (m) => luhn(m.replace(/\D/g, "")));
  sub(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "EMAIL");
  sub(/(?<![\d])(?:\+972|972|0)[\s-]?(?:5\d|[2-4]|[8-9]|7\d)[\s-]?\d{3}[\s-]?\d{4}(?!\d)/g, "PHONE");
  sub(/(?<!\d)\d{9}(?!\d)/g, "ID9"); // Israeli ID number shape
  return { text, count };
}

export class NoEligibleProviderError extends Error {}
export class AllProvidersFailedError extends Error {}

export interface ProviderStats { id: string; ok: number; fail: number; avgMs: number; rateLimited: number; restingUntil: number }

export class Router {
  private fails = new Map<string, { n: number; openUntil: number }>();
  private stats = new Map<string, ProviderStats>();
  private calls = new Map<string, number[]>();
  private sticky = new Map<string, { id: string; at: number }>();
  private cache = new Map<string, { text: string; provider: string; at: number }>();
  constructor(private o: RouterOptions) {}
  private now() { return (this.o.now ?? Date.now)(); }
  private st(id: string) { let s = this.stats.get(id); if (!s) this.stats.set(id, (s = { id, ok: 0, fail: 0, avgMs: 0, rateLimited: 0, restingUntil: 0 })); return s; }
  health(): ProviderStats[] { return this.o.providers.map((p) => ({ ...this.st(p.id) })); }
  private underRpm(p: Provider) {
    if (!p.rpm) return true;
    const recent = (this.calls.get(p.id) ?? []).filter((t) => t > this.now() - 60_000); this.calls.set(p.id, recent);
    return recent.length < p.rpm;
  }
  private order(eligible: Provider[], session?: string) {
    let list = [...eligible];
    if (this.o.strategy === "fast") list.sort((a, b) => (this.st(a.id).avgMs || 1) - (this.st(b.id).avgMs || 1));
    if (this.o.strategy === "reliable") { const rate = (id: string) => { const s = this.st(id); return s.ok + s.fail ? s.ok / (s.ok + s.fail) : 0.5; }; list.sort((a, b) => rate(b.id) - rate(a.id)); }
    const hit = session ? this.sticky.get(session) : undefined;
    if (hit && this.now() - hit.at < (this.o.stickyMs ?? 1_800_000)) { const i = list.findIndex((p) => p.id === hit.id); if (i > 0) list = [list[i]!, ...list.slice(0, i), ...list.slice(i + 1)]; }
    return list;
  }

  async complete(prompt: string, sensitivity: Sensitivity = "internal", opts: { session?: string } = {}): Promise<{ text: string; provider: string; cached?: boolean }> {
    const eligible = this.o.providers.filter((p) => RANK[p.maxSensitivity] >= RANK[sensitivity]);
    if (!eligible.length) {
      throw new NoEligibleProviderError(`no provider is approved for "${sensitivity}" data; refusing to send`);
    }
    const ckey = this.o.cacheMs && sensitivity !== "secret" ? `${sensitivity}|${prompt}` : "";
    if (ckey) { const c = this.cache.get(ckey); if (c && this.now() - c.at < this.o.cacheMs!) return { text: c.text, provider: c.provider, cached: true }; }
    let lastErr = "";
    for (const p of this.order(eligible, opts.session)) {
      const st = this.fails.get(p.id);
      if (st && st.openUntil > this.now()) continue; // circuit open or resting after a 429
      if (!this.underRpm(p)) { lastErr = "RateBudget"; continue; }
      const r = p.maxSensitivity === "secret" ? { text: prompt, count: 0 } : redact(prompt);
      const t0 = this.now();
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), this.o.timeoutMs ?? 30_000);
      this.calls.set(p.id, [...(this.calls.get(p.id) ?? []), t0]);
      try {
        const text = await p.call(r.text, ac.signal);
        this.fails.delete(p.id);
        const ms = this.now() - t0, s = this.st(p.id); s.ok++; s.avgMs = s.avgMs ? Math.round(s.avgMs * 0.7 + ms * 0.3) : ms;
        if (opts.session) this.sticky.set(opts.session, { id: p.id, at: this.now() });
        if (ckey) this.cache.set(ckey, { text, provider: p.id, at: this.now() });
        this.o.log?.({ provider: p.id, ok: true, ms, promptChars: prompt.length, redactions: r.count });
        return { text, provider: p.id };
      } catch (e) {
        lastErr = (e as Error).name;
        const s = this.st(p.id); s.fail++;
        if (e instanceof RateLimitedError) { s.rateLimited++; s.restingUntil = this.now() + e.retryAfterMs; this.fails.set(p.id, { n: st?.n ?? 0, openUntil: s.restingUntil }); }
        else { const n = (st?.n ?? 0) + 1; this.fails.set(p.id, { n, openUntil: n >= (this.o.failuresBeforeOpen ?? 3) ? this.now() + (this.o.cooldownMs ?? 60_000) : 0 }); }
        this.o.log?.({ provider: p.id, ok: false, ms: this.now() - t0, promptChars: prompt.length, redactions: r.count, error: lastErr });
      } finally {
        clearTimeout(timer);
      }
    }
    throw new AllProvidersFailedError(`all eligible providers failed (${lastErr || "circuit open"})`);
  }
}
