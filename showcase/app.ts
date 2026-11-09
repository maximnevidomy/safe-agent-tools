// The app: a local web UI plus real endpoints that use the ten modules on live data.
// Hardening of the app itself (it is a local tool that reads folders and the network, so it must not be a way in):
//  - listens on 127.0.0.1 only; Host header must be localhost/127.0.0.1 (blocks DNS rebinding)
//  - every /api call needs a random per-run token that only the served page knows (blocks cross-site requests)
//  - folder tools are confined to DEMO_ROOTS (realpath, symlink safe)
//  - webhook endpoint is public by nature, so it is protected by Meta's HMAC signature instead of the token
//  - bodies are size-capped; results are shown with textContent only
import { randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { ApprovalGate } from "../src/approval-gate";
import { createClient } from "../src/bybit-readonly";
import { handleEvent, verifyChallenge, verifySignature } from "../src/ig-webhook";
import { LocalIndex } from "../src/local-index";
import { redact } from "../src/llm-router";
import { Deps, RateLimiter, SafeFetchError, safeFetch } from "../src/safe-fetch";
import { githubReadme, githubRepo, vetRepo } from "../src/safe-reach";
import { scanText } from "../src/skill-scanner";
import { scanProject, verdict as launchVerdict } from "../src/launch-check";
import { confine, launchScan, skillScan } from "./fsscan";
import { PAGE } from "./page";
import { pipeline, scenarios } from "./scenarios";

export interface AppOptions {
  roots: string[];
  port?: number;
  outboxDir: string;
  igSecret?: string;
  igVerifyToken?: string;
  githubToken?: string;
  gateSecret?: string;
  netDeps?: Deps; // tests inject a fake network; production uses the real, IP-pinned transport
  bybitFetch?: typeof fetch;
}
const MAX_BODY = 100_000;

export function createApp(o: AppOptions) {
  const token = randomBytes(24).toString("hex");
  const gate = new ApprovalGate(o.gateSecret ?? randomBytes(32).toString("hex"));
  const proposals = new Map<string, { text: string }>();
  const limiter = new RateLimiter(5, 0.2);
  const optedOut = new Set<string>(), seenMids = new Set<string>();
  fs.mkdirSync(o.outboxDir, { recursive: true });
  const outboxFile = path.join(o.outboxDir, "outbox.jsonl");
  const log = (entry: Record<string, unknown>) => fs.appendFileSync(outboxFile, JSON.stringify({ at: new Date().toISOString(), ...entry }) + "\n");
  const readOutbox = () => (fs.existsSync(outboxFile) ? fs.readFileSync(outboxFile, "utf8").trim().split("\n").filter(Boolean).slice(-20).map((l) => JSON.parse(l)) : []);

  const readRaw = (req: http.IncomingMessage): Promise<Buffer> => new Promise((resolve, reject) => {
    let n = 0; const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => { n += c.length; if (n > MAX_BODY) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
  const send = (res: http.ServerResponse, code: number, body: unknown, type = "application/json") => {
    res.writeHead(code, { "Content-Type": type + "; charset=utf-8", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'" });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const tokenOk = (given: unknown) => { const a = Buffer.from(String(given ?? "")), b = Buffer.from(token); return a.length === b.length && timingSafeEqual(a, b); };

  const server = http.createServer(async (req, res) => {
    try {
      const port = (server.address() as { port: number } | null)?.port ?? o.port;
      const host = String(req.headers.host ?? "");
      if (!(host === `127.0.0.1:${port}` || host === `localhost:${port}`)) return send(res, 403, { error: "bad host" });
      const url = new URL(req.url ?? "/", "http://localhost");

      // Instagram webhook: public endpoint, authenticated by Meta's signature, not by the UI token.
      if (url.pathname === "/webhook/instagram") {
        if (!o.igSecret || !o.igVerifyToken) return send(res, 503, { error: "webhook not configured (set IG_APP_SECRET and IG_VERIFY_TOKEN)" });
        if (req.method === "GET") {
          const c = verifyChallenge(Object.fromEntries(url.searchParams), o.igVerifyToken);
          return c ? send(res, 200, c, "text/plain") : send(res, 403, { error: "verification failed" });
        }
        if (req.method === "POST") {
          const raw = await readRaw(req);
          if (!verifySignature(raw, String(req.headers["x-hub-signature-256"] ?? ""), o.igSecret)) return send(res, 401, { error: "bad signature" });
          const outcomes = await handleEvent(JSON.parse(raw.toString("utf8")), {
            store: { isOptedOut: async (s) => optedOut.has(s), setOptedOut: async (s, v) => void (v ? optedOut.add(s) : optedOut.delete(s)), isHandedOver: async () => false, seen: async (m) => (seenMids.has(m) ? true : (seenMids.add(m), false)) },
            rules: [{ keywords: ["price", "מחיר"], reply: "Thanks for asking! Prices are on the website." }, { keywords: ["hello", "hi", "שלום"], reply: "Hi! How can I help?" }],
            send: async (to, text) => log({ type: "ig_reply_logged", to, text, note: "not sent: add a Page token to enable sending" }),
            allow: (s) => limiter.allow(s),
          });
          return send(res, 200, { ok: true, outcomes });
        }
        return send(res, 405, { error: "method" });
      }

      if (req.method === "GET" && url.pathname === "/") return send(res, 200, PAGE.replace("__TOKEN__", token), "text/html");
      if (!url.pathname.startsWith("/api/")) return send(res, 404, { error: "not found" });
      if (!tokenOk(req.headers["x-demo-token"])) return send(res, 401, { error: "missing or wrong token" });

      if (req.method === "GET" && url.pathname === "/api/scenarios") return send(res, 200, scenarios.map((s, i) => ({ id: i, module: s.module, kind: s.kind, name: s.name })));
      if (req.method === "GET" && url.pathname === "/api/outbox") return send(res, 200, readOutbox());
      if (req.method !== "POST") return send(res, 405, { error: "method" });
      const raw = await readRaw(req);
      const b = raw.length ? JSON.parse(raw.toString("utf8")) : {};

      switch (url.pathname) {
        case "/api/run": {
          const s = scenarios[Number(b.id)]; if (!s) return send(res, 400, { error: "unknown scenario" });
          const t0 = performance.now(); let ok = false; try { ok = await s.run(); } catch { ok = false; }
          return send(res, 200, { ok, ms: Math.round(performance.now() - t0) });
        }
        case "/api/pipeline": return send(res, 200, await pipeline());

        // ---- live tools (real network and real files) ----
        case "/api/live/repo": {
          const m = /^(?:https?:\/\/github\.com\/)?([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/.exec(String(b.repo ?? "").trim());
          if (!m) return send(res, 400, { error: "use owner/repo or a github.com URL" });
          // A stale GITHUB_TOKEN must not break public lookups: retry once without it on 401.
          const gh = async <T,>(fn: (token?: string) => Promise<T>): Promise<T> => {
            try { return await fn(o.githubToken); } catch (e) { if (o.githubToken && /HTTP 401/.test((e as Error).message)) return fn(undefined); throw e; }
          };
          const meta = await gh((t) => githubRepo(m[1]!, m[2]!, { token: t }, o.netDeps));
          const readme = await gh((t) => githubReadme(m[1]!, m[2]!, { token: t }, o.netDeps));
          const scan = scanText("README", readme);
          return send(res, 200, { meta, ...vetRepo(meta, scan.findings), readmeVerdict: scan.verdict, readmeFindings: scan.findings.slice(0, 20) });
        }
        case "/api/live/bybit": {
          const symbol = String(b.symbol ?? "BTCUSDT").toUpperCase();
          if (!/^[A-Z0-9]{3,20}$/.test(symbol)) return send(res, 400, { error: "bad symbol" });
          const network = b.mainnet ? "mainnet" : "testnet";
          const c = createClient({ network, confirmLive: network === "mainnet", fetchImpl: o.bybitFetch });
          const r = await c.call("get_tickers", { category: "spot", symbol });
          const t = r.list?.[0] ?? null;
          return send(res, 200, { network, symbol, last: t?.lastPrice ?? null, change24h: t?.price24hPcnt ?? null, volume24h: t?.volume24h ?? null, note: "read-only public market data; no key used" });
        }
        case "/api/live/fetch": {
          const allow = String(b.allow ?? "").split(/[\s,]+/).filter(Boolean);
          try {
            const r = await safeFetch(String(b.url ?? ""), { allowHosts: allow, maxBytes: 200_000 }, o.netDeps);
            return send(res, 200, { allowed: true, status: r.status, bytes: r.body.length, preview: redact(r.body.toString("utf8").slice(0, 3000)).text });
          } catch (e) {
            if (e instanceof SafeFetchError) return send(res, 200, { allowed: false, code: e.code, message: e.message });
            throw e;
          }
        }
        case "/api/live/folder": {
          const root = confine(String(b.path ?? ""), o.roots);
          if (b.action === "launch") return send(res, 200, launchScan(root));
          if (b.action === "skills") return send(res, 200, skillScan(root));
          if (b.action === "search") {
            const idx = LocalIndex.build(root);
            const reasons: Record<string, number> = {};
            for (const s of idx.skipped) reasons[s.reason] = (reasons[s.reason] ?? 0) + 1;
            return send(res, 200, { indexed: idx.size, skipped: reasons, hits: idx.search(String(b.query ?? ""), 8) });
          }
          return send(res, 400, { error: "unknown action" });
        }

        // ---- approval gate: nothing is published until a human clicks Approve on the exact text ----
        case "/api/gate/propose": {
          const text = String(b.text ?? "").slice(0, 2000).trim(); if (!text) return send(res, 400, { error: "text required" });
          const p = gate.propose("publish", { text }, text.slice(0, 120));
          proposals.set(p.id, { text });
          return send(res, 200, { id: p.id, summary: p.summary });
        }
        case "/api/gate/approve": {
          const id = String(b.id ?? ""), prop = proposals.get(id); if (!prop) return send(res, 404, { error: "unknown or already handled proposal" });
          proposals.delete(id);
          const tok = gate.approve(id, "local-user");
          await gate.execute(tok, "publish", { text: prop.text }, async () => log({ type: "published", text: prop.text }));
          return send(res, 200, { published: true });
        }
        case "/api/gate/reject": { proposals.delete(String(b.id ?? "")); log({ type: "rejected", id: String(b.id ?? "") }); return send(res, 200, { ok: true }); }
        // ---- paste-in playgrounds (pure functions) ----
        case "/api/play/redact": { const r = redact(String(b.text ?? "").slice(0, 20000)); return send(res, 200, { text: r.text, count: r.count }); }
        case "/api/play/skill": return send(res, 200, scanText("input", String(b.text ?? "").slice(0, 50000)));
        case "/api/play/launch": { const f = scanProject([{ path: "input.sql", text: String(b.text ?? "").slice(0, 50000) }]); return send(res, 200, { verdict: launchVerdict(f), findings: f }); }
        default: return send(res, 404, { error: "not found" });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : "error";
      return send(res, 400, { error: msg.slice(0, 300) });
    }
  });
  return { server, token, gate };
}
