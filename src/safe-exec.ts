// safe-exec: run CLI tools for an agent ("CLI-Anything" style) without a shell.
// Defences: commands are looked up by NAME in an allowlist mapped to absolute paths (the agent never supplies
// a path), no shell so metacharacters are inert, argument count/length/NUL checks, optional per-command argument
// rules, a scrubbed environment (secrets are not inherited), a hard timeout and an output cap.
import { spawn } from "node:child_process";

export interface CommandSpec {
  path: string; // absolute path to the binary
  maxArgs?: number;
  checkArgs?: (args: string[]) => string | null; // return an error message to reject
}
export interface ExecPolicy {
  commands: Record<string, CommandSpec>;
  timeoutMs?: number;
  maxOutputBytes?: number;
  env?: Record<string, string>; // the ONLY environment the child gets
  cwd?: string;
}
export class ExecError extends Error {
  constructor(public code: string, msg: string) { super(msg); }
}
export interface ExecResult { code: number | null; stdout: string; stderr: string; truncated: boolean; timedOut: boolean }

export function safeExec(policy: ExecPolicy, name: string, args: string[] = []): Promise<ExecResult> {
  if (typeof name !== "string" || !Object.prototype.hasOwnProperty.call(policy.commands, name)) {
    return Promise.reject(new ExecError("not_allowed", `command "${String(name).slice(0, 40)}" is not allowlisted`));
  }
  const spec = policy.commands[name]!;
  if (!spec.path.startsWith("/")) return Promise.reject(new ExecError("bad_policy", "command path must be absolute"));
  if (!Array.isArray(args) || args.some((a) => typeof a !== "string")) return Promise.reject(new ExecError("bad_args", "args must be strings"));
  if (args.length > (spec.maxArgs ?? 16)) return Promise.reject(new ExecError("bad_args", "too many arguments"));
  if (args.some((a) => a.length > 2000 || a.includes("\0"))) return Promise.reject(new ExecError("bad_args", "argument too long or contains NUL"));
  const why = spec.checkArgs?.(args);
  if (why) return Promise.reject(new ExecError("rejected_args", why));

  const maxOut = policy.maxOutputBytes ?? 100_000;
  const timeoutMs = policy.timeoutMs ?? 10_000;
  return new Promise((resolve, reject) => {
    const child = spawn(spec.path, args, { shell: false, env: { ...(policy.env ?? {}) }, cwd: policy.cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "", truncated = false, timedOut = false;
    const add = (cur: string, d: Buffer) => {
      if (cur.length + d.length > maxOut) { truncated = true; child.kill("SIGKILL"); return cur + d.toString("utf8", 0, Math.max(0, maxOut - cur.length)); }
      return cur + d.toString("utf8");
    };
    child.stdout.on("data", (d: Buffer) => { out = add(out, d); });
    child.stderr.on("data", (d: Buffer) => { err = add(err, d); });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
    child.on("error", (e) => { clearTimeout(timer); reject(new ExecError("spawn_failed", e.message)); });
    child.on("close", (code) => { clearTimeout(timer); resolve({ code, stdout: out, stderr: err, truncated, timedOut }); });
  });
}
