import { describe, expect, it } from "vitest";
import { AllProvidersFailedError, LogEntry, NoEligibleProviderError, Provider, Router, redact } from "../src/llm-router";

const prov = (id: string, max: Provider["maxSensitivity"], fn: (p: string) => Promise<string>): Provider => ({
  id, maxSensitivity: max, call: (p) => fn(p),
});

describe("redact", () => {
  it("removes emails, phones, tokens, keys, valid cards and ids", () => {
    const input = [
      "mail me at dana@example.com", "call 052-123-4567", "key sk-abcdefghijklmnopqrstuv",
      "aws AKIAABCDEFGHIJKLMNOP", "gh ghp_" + "a".repeat(36), "card 4111 1111 1111 1111", "id 123456789",
      "Authorization: Bearer abcdefghijklmnop1234567890",
      "jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY.abcdefghijk123",
    ].join("\n");
    const { text, count } = redact(input);
    for (const leak of ["dana@example.com", "052-123-4567", "sk-abcdef", "AKIAABC", "ghp_", "4111", "123456789", "abcdefghijklmnop1234", "eyJhbGci"]) {
      expect(text).not.toContain(leak);
    }
    expect(count).toBeGreaterThanOrEqual(9);
  });
  it("keeps ordinary text and invalid card-like numbers", () => {
    expect(redact("workout plan for 4 weeks, 3 sets of 12").count).toBe(0);
    expect(redact("order 1234 5678 9012 3456").text).toContain("1234 5678 9012 3456"); // fails Luhn
  });
});

describe("Router", () => {
  it("never sends secret data to a provider that is not approved for it", async () => {
    const r = new Router({ providers: [prov("free", "public", async () => "x"), prov("ours", "internal", async () => "y")] });
    await expect(r.complete("hi", "secret")).rejects.toBeInstanceOf(NoEligibleProviderError);
  });
  it("skips providers below the request level and fails over on error", async () => {
    const seen: string[] = [];
    const r = new Router({
      providers: [
        prov("free", "public", async () => { seen.push("free"); return "free"; }),
        prov("bad", "internal", async () => { seen.push("bad"); throw new Error("down"); }),
        prov("good", "internal", async () => { seen.push("good"); return "ok"; }),
      ],
    });
    const out = await r.complete("hello", "internal");
    expect(out).toEqual({ text: "ok", provider: "good" });
    expect(seen).toEqual(["bad", "good"]); // "free" is never contacted for internal data
  });
  it("redacts before sending to non-local providers, but not to a local one", async () => {
    let remote = "", local = "";
    const r1 = new Router({ providers: [prov("remote", "internal", async (p) => { remote = p; return "x"; })] });
    await r1.complete("write to a@b.co");
    expect(remote).not.toContain("a@b.co");
    const r2 = new Router({ providers: [prov("local", "secret", async (p) => { local = p; return "x"; })] });
    await r2.complete("write to a@b.co", "secret");
    expect(local).toContain("a@b.co");
  });
  it("logs metadata only", async () => {
    const logs: LogEntry[] = [];
    const r = new Router({ providers: [prov("p", "internal", async () => "SECRET ANSWER")], log: (e) => logs.push(e) });
    await r.complete("my email is a@b.co");
    const dump = JSON.stringify(logs);
    expect(dump).not.toContain("a@b.co");
    expect(dump).not.toContain("SECRET ANSWER");
    expect(logs[0]).toMatchObject({ provider: "p", ok: true, redactions: 1 });
  });
  it("opens the circuit after repeated failures and recovers after the cooldown", async () => {
    let t = 0, calls = 0;
    const r = new Router({
      providers: [prov("flaky", "internal", async () => { calls++; throw new Error("x"); })],
      failuresBeforeOpen: 2, cooldownMs: 1000, now: () => t,
    });
    await expect(r.complete("a")).rejects.toBeInstanceOf(AllProvidersFailedError);
    await expect(r.complete("a")).rejects.toBeInstanceOf(AllProvidersFailedError);
    await expect(r.complete("a")).rejects.toBeInstanceOf(AllProvidersFailedError);
    expect(calls).toBe(2); // third call skipped, circuit open
    t = 1500;
    await expect(r.complete("a")).rejects.toBeInstanceOf(AllProvidersFailedError);
    expect(calls).toBe(3);
  });
});

import { RateLimitedError } from "../src/llm-router";
describe("router upgrades", () => {
  const mk = (id: string, fn: () => Promise<string>, extra: object = {}) => ({ id, maxSensitivity: "public" as const, call: fn, ...extra });
  it("a 429 rests the provider for the time it asked, then it is used again", async () => {
    let t = 0; let a429 = true;
    const r = new Router({ now: () => t, providers: [mk("a", async () => { if (a429) throw new RateLimitedError(10_000); return "A"; }), mk("b", async () => "B")] });
    expect((await r.complete("hi", "public")).provider).toBe("b");
    a429 = false; expect((await r.complete("hi", "public")).provider).toBe("b"); // still resting
    t = 11_000; expect((await r.complete("hi", "public")).provider).toBe("a");
    expect(r.health()[0]!.rateLimited).toBe(1);
  });
  it("stays under a provider's requests-per-minute budget", async () => {
    let t = 0; const r = new Router({ now: () => t, providers: [mk("a", async () => "A", { rpm: 2 }), mk("b", async () => "B")] });
    const got = []; for (let i = 0; i < 3; i++) got.push((await r.complete("hi", "public")).provider);
    expect(got).toEqual(["a", "a", "b"]); t = 61_000; expect((await r.complete("hi", "public")).provider).toBe("a");
  });
  it("fast strategy prefers the quicker provider once it has been observed", async () => {
    let t = 0; const slow = async () => { t += 500; return "S"; }; const quick = async () => { t += 10; return "Q"; };
    const r = new Router({ now: () => t, strategy: "fast", providers: [mk("slow", slow), mk("quick", quick)] });
    await r.complete("x", "public"); // slow first (nothing observed), takes 500
    expect((await r.complete("y", "public")).provider).toBe("quick");
  });
  it("sticky sessions keep a conversation on one provider; others do not follow", async () => {
    let t = 0; let aDown = true;
    const r = new Router({ now: () => t, providers: [mk("a", async () => { if (aDown) throw new Error("x"); return "A"; }), mk("b", async () => "B")] });
    expect((await r.complete("1", "public", { session: "s1" })).provider).toBe("b");
    aDown = false; expect((await r.complete("2", "public", { session: "s1" })).provider).toBe("b");
    expect((await r.complete("3", "public", { session: "s2" })).provider).toBe("a");
  });
  it("opt-in cache serves repeats but never for secret data", async () => {
    let n = 0; const r = new Router({ cacheMs: 1000, providers: [{ id: "L", maxSensitivity: "secret", call: async () => String(++n) }] });
    expect((await r.complete("q", "internal")).cached).toBeUndefined(); expect((await r.complete("q", "internal")).cached).toBe(true);
    await r.complete("q", "secret"); await r.complete("q", "secret"); expect(n).toBe(3);
  });
});
