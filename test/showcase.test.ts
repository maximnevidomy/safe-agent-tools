import { describe, expect, it } from "vitest";
import { pipeline, scenarios } from "../showcase/scenarios";

describe("showcase: every module works and every attack is stopped", () => {
  for (const s of scenarios) it(`${s.module} [${s.kind}] ${s.name}`, async () => expect(await s.run()).toBe(true));
  it("covers all ten modules with one legit and one attack each", () => {
    const mods = new Set(scenarios.map((s) => s.module));
    expect(mods.size).toBe(10);
    for (const m of mods) expect(scenarios.filter((s) => s.module === m).map((s) => s.kind).sort()).toEqual(["attack", "legit"]);
  });
  it("the end-to-end agent pipeline passes", async () => {
    const p = await pipeline();
    expect(p.steps.filter((s) => !s.ok)).toEqual([]);
    expect(p.ok).toBe(true);
  });
});
