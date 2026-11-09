import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LocalIndex } from "../src/local-index";

let root: string, outside: string, idx: LocalIndex;
beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "li-root-"));
  outside = fs.mkdtempSync(path.join(os.tmpdir(), "li-out-"));
  fs.writeFileSync(path.join(root, "plan.md"), "Weekly workout plan for squat day. Contact coach@example.com about squat form.");
  fs.writeFileSync(path.join(root, "recipes.md"), "High protein recipes with chicken and rice.");
  fs.writeFileSync(path.join(root, ".env"), "SUPABASE_SERVICE_ROLE_KEY=topsecretsquat");
  fs.writeFileSync(path.join(root, "id_rsa"), "squat PRIVATE");
  fs.writeFileSync(path.join(root, ".env.example"), "EXAMPLE_KEY=squat");
  fs.mkdirSync(path.join(root, "node_modules"));
  fs.writeFileSync(path.join(root, "node_modules", "x.md"), "squat in deps");
  fs.writeFileSync(path.join(outside, "passwd.txt"), "root:x:0:0 squat");
  fs.symlinkSync(path.join(outside, "passwd.txt"), path.join(root, "link.txt"));
  fs.symlinkSync(outside, path.join(root, "linkdir"));
  fs.writeFileSync(path.join(root, "bin.md"), Buffer.from([0x73, 0x71, 0, 0x75]));
  idx = LocalIndex.build(root);
});
afterAll(() => { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(outside, { recursive: true, force: true }); });

describe("LocalIndex", () => {
  it("finds relevant files ranked by relevance", () => {
    const r = idx.search("squat workout");
    expect(r[0]!.path).toBe("plan.md");
  });
  it("never indexes secrets, symlinks, dependency folders or binary files", () => {
    const paths = idx.search("squat", 20).map((x) => x.path);
    expect(paths).not.toContain(".env");
    expect(paths).not.toContain("id_rsa");
    expect(paths).not.toContain("link.txt");
    expect(paths.some((p) => p.includes("node_modules") || p.includes("linkdir"))).toBe(false);
    expect(idx.search("topsecretsquat")).toEqual([]);
    const reasons = Object.fromEntries(idx.skipped.map((s) => [s.rel, s.reason]));
    expect(reasons[".env"]).toBe("secret_file");
    expect(reasons["link.txt"]).toBe("symlink");
  });
  it("keeps .env.example (it holds no secrets)", () => {
    expect(idx.search("EXAMPLE_KEY").map((x) => x.path)).toContain(".env.example");
  });
  it("redacts personal data in snippets", () => {
    const hit = idx.search("squat form")[0]!;
    expect(hit.snippet).not.toContain("coach@example.com");
  });
  it("confines readFile to indexed files inside the root", () => {
    expect(idx.readFile("plan.md")).toContain("workout");
    for (const bad of ["../x", "/etc/passwd", ".env", "link.txt", "linkdir/passwd.txt", "plan.md\0", "node_modules/x.md"]) {
      expect(() => idx.readFile(bad), bad).toThrow();
    }
  });
});

describe("local-index upgrades", () => {
  const mk = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "li-"));
    fs.writeFileSync(path.join(dir, "a.ts"), "// helpers\nexport function getUserName(id: string) {\n  return id;\n}\nexport class OrderService {}\nconst MAX_RETRY_COUNT = 3;\n");
    fs.writeFileSync(path.join(dir, "b.py"), "def fetch_user_name(x):\n    return x\n");
    return LocalIndex.build(dir);
  };
  it("finds camelCase and snake_case code by its parts and reports the line", () => {
    const idx = mk(); const r = idx.search("user name", 5);
    expect(r.map((x) => x.path).sort()).toEqual(["a.ts", "b.py"]); expect(r.find((x) => x.path === "a.ts")!.line).toBeGreaterThanOrEqual(1);
    expect(idx.search("retry")[0]!.path).toBe("a.ts");
  });
  it("go-to-definition finds functions, classes, constants and python defs, and rejects odd input", () => {
    const idx = mk();
    expect(idx.def("getUserName")).toEqual([expect.objectContaining({ path: "a.ts", line: 2, kind: "function" })]);
    expect(idx.def("OrderService")[0]!.kind).toBe("class");
    expect(idx.def("MAX_RETRY_COUNT")[0]!.line).toBe(6);
    expect(idx.def("fetch_user_name")[0]).toEqual(expect.objectContaining({ path: "b.py", kind: "def" }));
    expect(idx.def("nothing")).toEqual([]); expect(idx.def(".*")).toEqual([]); expect(idx.def("a(b")).toEqual([]);
  });
});
