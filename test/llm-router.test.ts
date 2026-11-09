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
