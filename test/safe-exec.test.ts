import { describe, expect, it } from "vitest";
import { ExecError, ExecPolicy, safeExec } from "../src/safe-exec";

const PRINT = "console.log(process.argv[1])";
const SLEEP = "setTimeout(()=>{},5000)";
const policy: ExecPolicy = {
  commands: {
    echo: { path: process.execPath, checkArgs: (a) => (a[0] === "-e" && a[1] === PRINT ? null : "only the fixed print script is allowed") },
    sleep: { path: process.execPath, checkArgs: (a) => (a[0] === "-e" && a[1] === SLEEP ? null : "only the fixed sleep script is allowed") },
    node: { path: process.execPath, checkArgs: (a) => (a[0] === "-e" ? null : "only -e allowed in tests") },
  },
  timeoutMs: 800,
  maxOutputBytes: 1000,
  env: process.platform === "win32" ? { SystemRoot: process.env.SystemRoot ?? "" } : {},
};
const code = async (p: Promise<unknown>) => { try { await p; } catch (e) { return (e as ExecError).code; } return "none"; };

describe("safeExec", () => {
  it("runs an allowlisted command", async () => {
    const r = await safeExec(policy, "echo", ["-e", PRINT, "hello"]);
    expect(r.stdout.trim()).toBe("hello");
  });
  it("treats shell metacharacters as literal text (no injection)", async () => {
    const r = await safeExec(policy, "echo", ["-e", PRINT, "hi; echo PWNED && cat /etc/passwd | $(whoami) `id`"]);
    expect(r.stdout).toContain("hi; echo PWNED");
    expect(r.stdout.split("\n").filter((l) => l.trim() === "PWNED")).toHaveLength(0);
  });
  it("rejects unknown commands, paths, and prototype names", async () => {
    for (const n of ["rm", "/bin/rm", "C:\\Windows\\System32\\cmd.exe", "../bin/sh", "sh", "cmd", "constructor", "__proto__", "toString"]) {
      expect(await code(safeExec(policy, n, []))).toBe("not_allowed");
    }
  });
  it("rejects bad arguments", async () => {
    expect(await code(safeExec(policy, "echo", ["-e", PRINT, "a\0b"]))).toBe("bad_args");
    expect(await code(safeExec(policy, "echo", Array(40).fill("x")))).toBe("bad_args");
    expect(await code(safeExec(policy, "echo", [5 as unknown as string]))).toBe("bad_args");
    expect(await code(safeExec(policy, "node", ["-p", "1"]))).toBe("rejected_args");
  });
  it("does not leak parent environment secrets to the child", async () => {
    process.env.SUPER_SECRET_TOKEN = "leak-me";
    const r = await safeExec(policy, "node", ["-e", "console.log(process.env.SUPER_SECRET_TOKEN ?? 'absent')"]);
    expect(r.stdout.trim()).toBe("absent");
    delete process.env.SUPER_SECRET_TOKEN;
  });
  it("kills a command that runs too long", async () => {
    const r = await safeExec(policy, "sleep", ["-e", SLEEP]);
    expect(r.timedOut).toBe(true);
  });
  it("caps runaway output", async () => {
    const r = await safeExec({ ...policy, timeoutMs: 5000 }, "node", ["-e", "setInterval(()=>process.stdout.write('x'.repeat(500)),1)"]);
    expect(r.truncated).toBe(true);
    expect(r.stdout.length).toBeLessThanOrEqual(1000);
  });
});
