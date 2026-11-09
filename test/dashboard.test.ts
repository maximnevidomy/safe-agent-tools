import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createApp } from "../showcase/app";
import { BENIGN_SKILLS, benignFalseAlarms, runAttacks } from "../showcase/attacks";
import { buildDashboard } from "../showcase/dashboard";
import { TOOLS } from "../showcase/originals";

const get = (port: number, p: string, host: string, method = "GET") => new Promise<{ status: number; body: string }>((resolve, reject) => {
  const r = http.request({ host: "127.0.0.1", port, path: p, method, headers: { Host: host } }, (res) => { let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => resolve({ status: res.statusCode!, body: b })); });
  r.on("error", reject); r.end();
});

describe("attack scores", () => {
  it("every hardened tool stops every applicable attack; every naive baseline is worse", async () => {
    const s = await runAttacks();
    for (const t of TOOLS) { expect(s[t.id].safeScore, t.id).toBe(100); expect(s[t.id].naiveScore, t.id).toBeLessThan(50); expect(s[t.id].applicable).toBeGreaterThanOrEqual(4); }
  }, 60_000);
  it("harmless skills raise no block verdict", () => { expect(BENIGN_SKILLS.length).toBeGreaterThan(2); expect(benignFalseAlarms()).toBe(0); });
});

describe("dashboard + public host", () => {
  it("renders all ten tools, the disclaimer and no script tags", async () => {
    const html = await buildDashboard({ generatedAt: "test", commit: "abc" });
    for (const t of TOOLS) expect(html).toContain(`id="${t.id}"`);
    expect(html).toContain("not</b> the original project");
    expect(html).not.toMatch(/<script/i);
  }, 60_000);
  it("public hostname gets the dashboard only; the workbench stays local", async () => {
    const app = createApp({ roots: [os.tmpdir()], outboxDir: fs.mkdtempSync(path.join(os.tmpdir(), "pub-")), publicHost: "demo.example.com", dashboardHtml: async () => "<h1>dash</h1>" });
    await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
    const port = (app.server.address() as AddressInfo).port;
    try {
      expect((await get(port, "/", "demo.example.com")).body).toContain("dash");
      expect((await get(port, "/dashboard", "demo.example.com")).status).toBe(200);
      for (const p of ["/api/scenarios", "/api/outbox", "/api/scan", "/robots.txt"]) expect((await get(port, p, "demo.example.com")).status, p).toBe(404);
      expect((await get(port, "/", "demo.example.com", "POST")).status).toBe(404);
      expect((await get(port, "/", "evil.example.com")).status).toBe(403);
      expect((await get(port, "/dashboard", `127.0.0.1:${port}`)).status).toBe(200);
      expect((await get(port, "/webhook/instagram", "demo.example.com")).status).toBe(503); // reachable, but authenticated by signature, not configured here
    } finally { await new Promise<void>((r) => app.server.close(() => r())); }
  });
  it("without publicHost, a foreign Host is refused", async () => {
    const app = createApp({ roots: [os.tmpdir()], outboxDir: fs.mkdtempSync(path.join(os.tmpdir(), "pub-")) });
    await new Promise<void>((r) => app.server.listen(0, "127.0.0.1", r));
    const port = (app.server.address() as AddressInfo).port;
    try { expect((await get(port, "/", "demo.example.com")).status).toBe(403); } finally { await new Promise<void>((r) => app.server.close(() => r())); }
  });
});
