import { describe, expect, it } from "vitest";
import { COMPARE } from "../showcase/compare";
import { TOOLS } from "../showcase/originals";

describe("original vs ours table", () => {
  it("every tool has an honest comparison, including at least one gap or deliberate omission", () => {
    for (const t of TOOLS) {
      const rows = COMPARE[t.id]; expect(rows.length, t.id).toBeGreaterThanOrEqual(3);
      expect(rows.some((r) => r.status === "missing" || r.status === "by-design" || r.status === "partial"), `${t.id} lists no gap`).toBe(true);
      for (const r of rows) { expect(r.what && r.original && r.ours).toBeTruthy(); }
    }
  });
});
