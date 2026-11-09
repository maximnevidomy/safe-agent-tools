// safe-fetch: an "API Anything" style fetcher that cannot be turned against our own network (SSRF).
// Defences: mandatory host allowlist, https only, no URL credentials, port allowlist, every resolved IP
// checked against private/reserved ranges, the connection is pinned to the checked IP (no DNS rebinding),
// redirects re-validated hop by hop, response size and time caps.
import dns from "node:dns/promises";
import https from "node:https";
import net from "node:net";

export class SafeFetchError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = "SafeFetchError";
  }
}

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((a, o) => a * 256 + Number(o), 0);
}
const V4_BLOCKS: Array<[string, number]> = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

export function isBlockedIp(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 4) {
    const n = v4ToInt(ip);
    return V4_BLOCKS.some(([base, bits]) => {
      const size = 2 ** (32 - bits);
      const start = Math.floor(v4ToInt(base) / size) * size;
      return n >= start && n < start + size;
    });
  }
  if (kind === 6) {
    const lower = ip.toLowerCase();
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/) ?? lower.match(/^64:ff9b::(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped?.[1]) return isBlockedIp(mapped[1]);
    // hex-form mapped addresses such as ::ffff:7f00:1
    const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const a = parseInt(hex[1]!, 16), b = parseInt(hex[2]!, 16);
      return isBlockedIp(`${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`);
    }
    if (lower === "::" || lower === "::1") return true;
    const first = parseInt(lower.split(":")[0] || "0", 16);
    if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
    if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
    if ((first & 0xff00) === 0xff00) return true; // multicast
    if (lower.startsWith("2001:db8")) return true; // documentation
    return false;
  }
  return true; // not an IP at all: treat as blocked
}

export function hostAllowed(host: string, allowHosts: string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return allowHosts.some((rule) => {
    const r = rule.toLowerCase();
    if (r.startsWith("*.")) return h.endsWith(r.slice(1)) && h.length > r.length - 1;
    return h === r;
  });
}

export interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}
export interface Deps {
  resolve(host: string): Promise<string[]>;
  get(args: { url: URL; ip: string; headers: Record<string, string>; timeoutMs: number; maxBytes: number }): Promise<RawResponse>;
}

export interface SafeFetchOptions {
  allowHosts: string[];
  allowPorts?: number[];
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
  headers?: Record<string, string>;
}

export const defaultDeps: Deps = {
  async resolve(host) {
    const r = await dns.lookup(host, { all: true });
    return r.map((x) => x.address);
  },
  get({ url, ip, headers, timeoutMs, maxBytes }) {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: ip, // connect to the address we validated, never re-resolve
          servername: url.hostname, // TLS SNI + certificate check against the real name
          port: url.port ? Number(url.port) : 443,
          path: url.pathname + url.search,
          method: "GET",
          headers: { ...headers, Host: url.host, "User-Agent": headers["User-Agent"] ?? "safe-agent-tools/0.1" },
          timeout: timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (c: Buffer) => {
            size += c.length;
            if (size > maxBytes) {
              req.destroy();
              reject(new SafeFetchError("too_large", `response exceeds ${maxBytes} bytes`));
              return;
            }
            chunks.push(c);
          });
          res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
          res.on("error", reject);
        },
      );
      req.on("timeout", () => {
        req.destroy();
        reject(new SafeFetchError("timeout", `no response within ${timeoutMs}ms`));
      });
      req.on("error", reject);
      req.end();
    });
  },
};

function validateUrl(raw: string | URL, opts: SafeFetchOptions): URL {
  if (!opts.allowHosts?.length) throw new SafeFetchError("no_allowlist", "allowHosts must not be empty");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SafeFetchError("bad_url", "invalid URL");
  }
  if (url.protocol !== "https:") throw new SafeFetchError("bad_scheme", "only https is allowed");
  if (url.username || url.password) throw new SafeFetchError("bad_url", "credentials in URL are not allowed");
  const port = url.port ? Number(url.port) : 443;
  if (!(opts.allowPorts ?? [443]).includes(port)) throw new SafeFetchError("bad_port", `port ${port} not allowed`);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new SafeFetchError("blocked_ip", "address is private or reserved");
  }
  if (!hostAllowed(host, opts.allowHosts)) throw new SafeFetchError("host_not_allowed", `host ${host} is not in the allowlist`);
  return url;
}

export async function safeFetch(
  rawUrl: string,
  opts: SafeFetchOptions,
  deps: Deps = defaultDeps,
): Promise<{ status: number; url: string; headers: RawResponse["headers"]; body: Buffer }> {
  const maxBytes = opts.maxBytes ?? 1_000_000;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxRedirects = opts.maxRedirects ?? 3;
  let current: string | URL = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const url = validateUrl(current, opts); // re-validated on every hop, including redirects
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const ips = net.isIP(host) ? [host] : await deps.resolve(host);
    if (!ips.length) throw new SafeFetchError("dns", "host did not resolve");
    // ALL records must be public: one private record is enough to reject (rebinding trick).
    if (ips.some(isBlockedIp)) throw new SafeFetchError("blocked_ip", "host resolves to a private or reserved address");
    const res = await deps.get({ url, ip: ips[0]!, headers: opts.headers ?? {}, timeoutMs, maxBytes });
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.location;
      const next = Array.isArray(loc) ? loc[0] : loc;
      if (!next) throw new SafeFetchError("bad_redirect", "redirect without Location");
      current = new URL(next, url);
      continue;
    }
    return { status: res.status, url: url.toString(), headers: res.headers, body: res.body };
  }
  throw new SafeFetchError("too_many_redirects", `more than ${maxRedirects} redirects`);
}

// Token bucket per caller key.
export class RateLimiter {
  private buckets = new Map<string, { tokens: number; at: number }>();
  constructor(private capacity: number, private refillPerSec: number, private now: () => number = Date.now) {}
  allow(key: string): boolean {
    const t = this.now();
    const b = this.buckets.get(key) ?? { tokens: this.capacity, at: t };
    b.tokens = Math.min(this.capacity, b.tokens + ((t - b.at) / 1000) * this.refillPerSec);
    b.at = t;
    const ok = b.tokens >= 1;
    if (ok) b.tokens -= 1;
    this.buckets.set(key, b);
    return ok;
  }
}
