// Exercises the REAL transport (defaultDeps.get): TLS with SNI + certificate validation against the real
// hostname, connect-to-pinned-IP, size cap and timeout. A local HTTPS server with a throwaway certificate
// stands in for the internet. (safeFetch itself still refuses 127.0.0.1; this test calls the transport directly.)
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultDeps, safeFetch } from "../src/safe-fetch";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tls-"));
let server: https.Server, port = 0, cert = "", haveOpenssl = true;

beforeAll(async () => {
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-subj", "/CN=api.test.example", "-addext", "subjectAltName=DNS:api.test.example"], { stdio: "ignore" });
  } catch { haveOpenssl = false; return; }
  cert = fs.readFileSync(path.join(dir, "c.pem"), "utf8");
  server = https.createServer({ key: fs.readFileSync(path.join(dir, "k.pem")), cert }, (req, res) => {
    if (req.url === "/big") { res.end("x".repeat(500_000)); return; }
    if (req.url === "/slow") { setTimeout(() => res.end("late"), 3000); return; }
    res.setHeader("X-Seen-Host", String(req.headers.host)); res.end("hello");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
  https.globalAgent.options.ca = cert; // trust the throwaway cert for this process
});
afterAll(() => { server?.close(); fs.rmSync(dir, { recursive: true, force: true }); });

const get = (p: string, extra = {}) => defaultDeps.get({ url: new URL(`https://api.test.example:${port}${p}`), ip: "127.0.0.1", headers: {}, timeoutMs: 1000, maxBytes: 100_000, ...extra });

describe("real transport (defaultDeps.get)", () => {
  it("connects to the pinned IP but validates TLS and sends Host for the real name", async () => {
    if (!haveOpenssl) return;
    const r = await get("/");
    expect(r.status).toBe(200);
    expect(r.body.toString()).toBe("hello");
    expect(String(r.headers["x-seen-host"])).toBe(`api.test.example:${port}`);
  });
  it("fails TLS verification when the certificate does not match the requested name", async () => {
    if (!haveOpenssl) return;
    await expect(defaultDeps.get({ url: new URL(`https://wrong.example:${port}/`), ip: "127.0.0.1", headers: {}, timeoutMs: 1000, maxBytes: 1000 })).rejects.toThrow();
  });
  it("enforces the size cap", async () => {
    if (!haveOpenssl) return;
    await expect(get("/big")).rejects.toMatchObject({ code: "too_large" });
  });
  it("enforces the timeout", async () => {
    if (!haveOpenssl) return;
    await expect(get("/slow", { timeoutMs: 300 })).rejects.toMatchObject({ code: "timeout" });
  });
  it("safeFetch still refuses a loopback target even when the name is allowlisted", async () => {
    await expect(safeFetch(`https://api.test.example:${port}/`, { allowHosts: ["api.test.example"], allowPorts: [port] }, { resolve: async () => ["127.0.0.1"], get: defaultDeps.get })).rejects.toMatchObject({ code: "blocked_ip" });
  });
});
