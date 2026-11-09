// Public site: the dashboard plus live "try it" endpoints. Built to run on the open internet (Render):
// no secrets in the process, no folder access, no stored input, per-visitor and global rate limits, size and time caps.
import http from "node:http";
import { RateLimiter } from "../src/safe-fetch";
import { CLIENT_JS } from "./client";
import { TRY_BY_ID, realCtx, type Ctx, type In } from "./try";
import type { ToolId } from "./attacks";

export interface PublicOptions { ctx?: Ctx; html: () => Promise<string>; clientIp?: (req: http.IncomingMessage) => string; limits?: { perIp: [number, number]; perIpNet: [number, number]; global: [number, number] } }
const MAX_BODY = 60_000, MAX_INFLIGHT = 8;

export const defaultClientIp = (req: http.IncomingMessage): string => {
  const cf = req.headers["cf-connecting-ip"]; if (typeof cf === "string" && cf) return cf.trim();
  const xff = req.headers["x-forwarded-for"]; const last = (Array.isArray(xff) ? xff.join(",") : xff ?? "").split(",").map((x) => x.trim()).filter(Boolean).pop();
  return last || req.socket.remoteAddress || "unknown";
};

export function createPublicApp(o: PublicOptions) {
  const ctx = o.ctx ?? realCtx(process.env.GITHUB_TOKEN);
  const ipOf = o.clientIp ?? defaultClientIp;
  const L = o.limits ?? { perIp: [20, 0.3], perIpNet: [6, 0.1], global: [200, 4] };
  const perIp = new RateLimiter(...L.perIp), perIpNet = new RateLimiter(...L.perIpNet), global = new RateLimiter(...L.global);
  let inflight = 0, page: Promise<string> | null = null;
  const getPage = () => (page ??= o.html().catch((e) => { page = null; throw e; }));

  const headers = (type: string, cache: string) => ({ "Content-Type": type + "; charset=utf-8", "Cache-Control": cache, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Strict-Transport-Security": "max-age=31536000", "Cross-Origin-Opener-Policy": "same-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" });
  const send = (res: http.ServerResponse, code: number, body: unknown, type = "application/json", cache = "no-store") => { res.writeHead(code, headers(type, cache)); res.end(typeof body === "string" ? body : JSON.stringify(body)); };
  const readBody = (req: http.IncomingMessage) => new Promise<string>((resolve, reject) => { let n = 0; const c: Buffer[] = []; req.on("data", (b: Buffer) => { n += b.length; if (n > MAX_BODY) { reject(new Error("big")); req.destroy(); } else c.push(b); }); req.on("end", () => resolve(Buffer.concat(c).toString("utf8"))); req.on("error", reject); });

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://x");
      if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, "ok", "text/plain");
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/dashboard")) return send(res, 200, await getPage(), "text/html", "public, max-age=60");
      if (req.method === "GET" && url.pathname === "/app.js") return send(res, 200, CLIENT_JS, "application/javascript", "public, max-age=300");
      const m = /^\/api\/try\/([a-z-]+)$/.exec(url.pathname);
      if (!m) return send(res, 404, { error: "not found" });
      if (req.method !== "POST") return send(res, 405, { error: "method" });
      const def = TRY_BY_ID.get(m[1] as ToolId); if (!def) return send(res, 404, { error: "unknown tool" });
      const origin = req.headers.origin; if (origin && (() => { try { return new URL(origin).host !== req.headers.host; } catch { return true; } })()) return send(res, 403, { error: "cross-site request refused" });
      if (!String(req.headers["content-type"] ?? "").startsWith("application/json")) return send(res, 415, { error: "send JSON" });
      const ip = ipOf(req);
      if (!global.allow("all") || !perIp.allow(ip) || (def.network && !perIpNet.allow(ip))) return send(res, 429, { error: "Too many tries. Wait a minute and try again." });
      if (inflight >= MAX_INFLIGHT) return send(res, 503, { error: "The server is busy. Try again in a few seconds." });
      let raw: unknown; try { raw = JSON.parse(await readBody(req)); } catch { return send(res, 400, { error: "invalid request" }); }
      const obj = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
      const input: Record<string, string> = {};
      for (const f of def.fields) { let v = typeof obj[f.name] === "string" ? (obj[f.name] as string) : f.value; if (v.length > f.max) v = v.slice(0, f.max); if (f.kind === "select" && !(f.options ?? []).includes(v)) v = f.value; input[f.name] = v; }
      inflight++;
      try {
        const out = await Promise.race([def.run(new Proxy(input, { get: (t, k) => (typeof k === "string" ? t[k] ?? "" : undefined) }) as In, ctx), new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timeout")), 20_000).unref())]);
        return send(res, 200, out);
      } catch { return send(res, 200, { verdict: "info", headline: "That request could not be completed. Try different input.", rows: [] }); }
      finally { inflight--; }
    } catch { try { send(res, 500, { error: "server error" }); } catch { /* socket gone */ } }
  });
  server.requestTimeout = 30_000; server.headersTimeout = 10_000; server.keepAliveTimeout = 5_000;
  return { server, ready: () => getPage().then(() => true) };
}
