import { describe, expect, it } from "vitest";
import { ApprovalGate, GateError, PostQueue } from "../src/approval-gate";
import { describePolicy, execJson } from "../src/safe-exec";
import { WatchFetch } from "../src/watch-fetch";
import type { Deps } from "../src/safe-fetch";

describe("approval queue", () => {
  const setup = () => {
    let t = 0; const g = new ApprovalGate("x".repeat(20), 600_000, () => t); const q = new PostQueue(g, () => t, 12 * 3_600_000); const sent: string[] = [];
    const approve = (payload: unknown, ttl = 86_400_000) => g.approve(g.propose("publish", payload, "p").id, "human", ttl);
    return { g, q, sent, approve, at: (x: number) => (t = x) };
  };
  it("publishes at its time with a valid approval, not before", async () => {
    const { q, sent, approve, at } = setup(); const post = { text: "hi" };
    q.schedule(approve(post), "publish", post, 3_600_000, async () => void sent.push("hi"));
    at(1000); expect(await q.tick()).toEqual([]); at(3_600_000); expect((await q.tick())[0]!.status).toBe("published"); expect(sent).toEqual(["hi"]);
    expect(await q.tick()).toEqual([]); // never twice
  });
  it("marks an overdue post missed and does not send it late", async () => {
    const { q, sent, approve, at } = setup(); const post = { text: "late" };
    q.schedule(approve(post), "publish", post, 1000, async () => void sent.push("late"));
    at(1000 + 13 * 3_600_000); const r = await q.tick(); expect(r[0]!.status).toBe("missed"); expect(sent).toEqual([]);
  });
  it("refuses a swapped payload or an expired approval", async () => {
    const { q, sent, approve, at } = setup();
    q.schedule(approve({ text: "a" }), "publish", { text: "EVIL" }, 10, async () => void sent.push("x"));
    q.schedule(approve({ text: "b" }, 5), "publish", { text: "b" }, 10, async () => void sent.push("y"));
    at(100); const r = await q.tick(); expect(r.map((x) => x.detail).sort()).toEqual(["expired", "payload_changed"]); expect(sent).toEqual([]);
  });
  it("a rejected proposal can never be approved; lifetime is capped", () => {
    const { g } = setup(); const p = g.propose("publish", {}, "s"); g.reject(p.id);
    expect(() => g.approve(p.id, "h")).toThrow(GateError);
    const p2 = g.propose("publish", {}, "s"); expect(() => g.approve(p2.id, "h", 8 * 86_400_000)).toThrow(/lifetime/);
  });
});

describe("safe-exec json", () => {
  const policy = { commands: { node: { path: process.execPath, description: "run node", usage: "node -p <expr>", maxArgs: 2, checkArgs: (a: string[]) => (a[0] === "-p" ? null : "only -p") } }, env: {}, timeoutMs: 3000 };
  it("returns a stable shape, parses json output and explains failures", async () => {
    const ok = await execJson(policy, "node", ["-p", 'JSON.stringify({a:1})']); expect(ok).toMatchObject({ ok: true, code: 0, data: { a: 1 } });
    const bad = await execJson(policy, "rm", ["-rf", "/"]); expect(bad.ok).toBe(false); expect(bad.error).toMatchObject({ class: "not_allowed" }); expect(bad.error!.next).toMatch(/describePolicy/);
    const rej = await execJson(policy, "node", ["-e", "1"]); expect(rej.error!.class).toBe("rejected_args");
    const fail = await execJson(policy, "node", ["-p", "process.exit(3)"]); expect(fail.error!.class).toBe("nonzero_exit");
  });
  it("describes the allowlist without revealing paths", () => {
    const d = describePolicy(policy); expect(d).toEqual([{ name: "node", description: "run node", usage: "node -p <expr>", maxArgs: 2 }]); expect(JSON.stringify(d)).not.toContain(process.execPath);
  });
});

describe("watch-fetch", () => {
  const mk = (): { deps: Deps; n: () => number; set: (b: string, s?: number) => void } => {
    let body = "v1", status = 200, n = 0;
    return { n: () => n, set: (b, s = 200) => { body = b; status = s; }, deps: { resolve: async () => ["93.184.216.34"], get: async () => { n++; return { status, headers: {}, body: Buffer.from(body) }; } } };
  };
  const o = { allowHosts: [] as string[], allowAnyPublic: true };
  it("serves repeats from the cache window and enforces a per-site budget", async () => {
    let t = 0; const m = mk(); const w = new WatchFetch({ cacheMs: 1000, perHostPerMin: 2, now: () => t, deps: m.deps });
    const a = await w.get("https://s.example/a", o); expect(a).toMatchObject({ ok: true, cached: false });
    expect(await w.get("https://s.example/a", o)).toMatchObject({ cached: true }); expect(m.n()).toBe(1);
    t = 2000; await w.get("https://s.example/b", o); t = 4000;
    const over = await w.get("https://s.example/c", o); expect(over).toMatchObject({ ok: false, error: { class: "budget" } });
  });
  it("turns failures into class plus next step", async () => {
    const m = mk(); const w = new WatchFetch({ deps: m.deps });
    m.set("x", 429); expect(await w.get("https://s.example/1", o)).toMatchObject({ ok: false, error: { class: "http_429" } });
    m.set("x", 403); const f = await w.get("https://s.example/2", o); expect(f).toMatchObject({ ok: false }); expect((f as { error: { next: string } }).error.next).toMatch(/official API/);
    const priv = await w.get("https://localhost/", o); expect(priv).toMatchObject({ ok: false, error: { class: "host_not_allowed" } });
    expect(await w.get("http://s.example/", o)).toMatchObject({ error: { class: "bad_scheme" } });
  });
  it("tracks changes between calls", () => {
    const w = new WatchFetch();
    expect(w.track("k", { sale: "79", regular: "129" })).toEqual({ first: true, changes: [] });
    expect(w.track("k", { sale: "59", regular: "129" })).toEqual({ first: false, changes: [{ field: "sale", before: "79", after: "59" }] });
    expect(w.track("k", { sale: "59", regular: "129" }).changes).toEqual([]);
  });
});
