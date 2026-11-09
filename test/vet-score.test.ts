import { describe, expect, it } from "vitest";
import { vetRepo } from "../src/safe-reach";

const NOW = Date.parse("2026-11-09T00:00:00Z");
const day = (n: number) => new Date(NOW - n * 86_400_000).toISOString();
describe("vetRepo score", () => {
  it("a healthy repo scores 100 and is OK", () => {
    const r = vetRepo({ stars: 500, license: "MIT", pushed_at: day(3), archived: false }, [], NOW);
    expect(r).toMatchObject({ score: 100, verdict: "ok" });
  });
  it("each risk removes explained points", () => {
    const r = vetRepo({ stars: 3, license: null, pushed_at: day(677), archived: false }, [{ severity: "high", rule: "pipe-to-shell" }], NOW);
    expect(r.verdict).toBe("reject"); expect(r.score).toBe(100 - 25 - 25 - 10 - 30);
    expect(r.signals.every((s) => typeof s.points === "number")).toBe(true);
  });
  it("counts each README rule once, however many lines match", () => {
    const f = { severity: "high" as const, rule: "pipe-to-shell" };
    expect(vetRepo({ stars: 500, license: "MIT", pushed_at: day(3), archived: false }, [f, f, f, f], NOW).score).toBe(70);
  });
  it("middling repo: review, score between", () => {
    const r = vetRepo({ stars: 5, license: "MIT", pushed_at: day(120), archived: false }, [], NOW);
    expect(r).toMatchObject({ verdict: "review", score: 80 });
  });
  it("never goes below zero", () => {
    const r = vetRepo({ stars: 0, license: null, pushed_at: day(900), archived: true }, Array(5).fill({ severity: "high", rule: "x" }), NOW);
    expect(r.score).toBe(0);
  });
});
