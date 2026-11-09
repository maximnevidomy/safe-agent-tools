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

export class Router {
  private fails = new Map<string, { n: number; openUntil: number }>();
  constructor(private o: RouterOptions) {}
  private now() { return (this.o.now ?? Date.now)(); }

  async complete(prompt: string, sensitivity: Sensitivity = "internal"): Promise<{ text: string; provider: string }> {
    const eligible = this.o.providers.filter((p) => RANK[p.maxSensitivity] >= RANK[sensitivity]);
    if (!eligible.length) {
      throw new NoEligibleProviderError(`no provider is approved for "${sensitivity}" data; refusing to send`);
    }
    let lastErr = "";
    for (const p of eligible) {
      const st = this.fails.get(p.id);
      if (st && st.openUntil > this.now()) continue; // circuit open
      const r = p.maxSensitivity === "secret" ? { text: prompt, count: 0 } : redact(prompt);
      const t0 = this.now();
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), this.o.timeoutMs ?? 30_000);
      try {
        const text = await p.call(r.text, ac.signal);
        this.fails.delete(p.id);
        this.o.log?.({ provider: p.id, ok: true, ms: this.now() - t0, promptChars: prompt.length, redactions: r.count });
        return { text, provider: p.id };
      } catch (e) {
        lastErr = (e as Error).name;
        const n = (st?.n ?? 0) + 1;
        this.fails.set(p.id, { n, openUntil: n >= (this.o.failuresBeforeOpen ?? 3) ? this.now() + (this.o.cooldownMs ?? 60_000) : 0 });
        this.o.log?.({ provider: p.id, ok: false, ms: this.now() - t0, promptChars: prompt.length, redactions: r.count, error: lastErr });
      } finally {
        clearTimeout(timer);
      }
    }
    throw new AllProvidersFailedError(`all eligible providers failed (${lastErr || "circuit open"})`);
  }
}
