// Local demo app: runs the REAL modules live and shows the results in a browser.
// Bound to 127.0.0.1 only, no CORS, small request bodies, results rendered with textContent (no HTML injection).
import http from "node:http";
import { redact } from "../src/llm-router";
import { scanProject, verdict } from "../src/launch-check";
import { Deps, SafeFetchError, safeFetch } from "../src/safe-fetch";
import { scanText } from "../src/skill-scanner";
import { pipeline, scenarios } from "./scenarios";
import { PAGE } from "./page";

const PORT = Number(process.env.PORT ?? 4173);
const MAX_BODY = 100_000;

const readJson = (req: http.IncomingMessage): Promise<any> => new Promise((resolve, reject) => {
  let n = 0; const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => { n += c.length; if (n > MAX_BODY) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
  req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch { reject(new Error("bad json")); } });
});
const send = (res: http.ServerResponse, code: number, body: unknown, type = "application/json") => {
  res.writeHead(code, { "Content-Type": type + "; charset=utf-8", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'", "Cache-Control": "no-store" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/") return send(res, 200, PAGE, "text/html");
    if (req.method === "GET" && url.pathname === "/api/scenarios") return send(res, 200, scenarios.map((s, i) => ({ id: i, module: s.module, kind: s.kind, name: s.name })));
    if (req.method !== "POST") return send(res, 404, { error: "not found" });
    const b = await readJson(req);
    if (url.pathname === "/api/run") {
      const s = scenarios[Number(b.id)]; if (!s) return send(res, 400, { error: "unknown scenario" });
      const t0 = performance.now(); let ok = false; try { ok = await s.run(); } catch { ok = false; }
      return send(res, 200, { ok, ms: Math.round(performance.now() - t0) });
    }
    if (url.pathname === "/api/pipeline") return send(res, 200, await pipeline());
    if (url.pathname === "/api/play/fetch") {
      const ip = String(b.ip || "93.184.216.34");
      const deps: Deps = { resolve: async () => [ip], get: async () => ({ status: 200, headers: {}, body: Buffer.from("ok") }) };
      try {
        const r = await safeFetch(String(b.url ?? ""), { allowHosts: String(b.allow ?? "").split(/[\s,]+/).filter(Boolean) }, deps);
        return send(res, 200, { allowed: true, message: `Allowed. Connection would be pinned to ${ip} (HTTP ${r.status}).` });
      } catch (e) {
        if (e instanceof SafeFetchError) return send(res, 200, { allowed: false, code: e.code, message: e.message });
        throw e;
      }
    }
    if (url.pathname === "/api/play/redact") { const r = redact(String(b.text ?? "").slice(0, 20000)); return send(res, 200, { text: r.text, count: r.count }); }
    if (url.pathname === "/api/play/skill") { const r = scanText("input", String(b.text ?? "").slice(0, 50000)); return send(res, 200, r); }
    if (url.pathname === "/api/play/launch") { const f = scanProject([{ path: "input.sql", text: String(b.text ?? "").slice(0, 50000) }]); return send(res, 200, { verdict: verdict(f), findings: f }); }
    return send(res, 404, { error: "not found" });
  } catch (e) {
    return send(res, 400, { error: (e as Error).message });
  }
});
server.listen(PORT, "127.0.0.1", () => console.log(`Demo running at http://127.0.0.1:${PORT}`));
