// safe-exec: run CLI tools for an agent ("CLI-Anything" style) without a shell.
// Defences: commands are looked up by NAME in an allowlist mapped to absolute paths (the agent never supplies
// a path), no shell so metacharacters are inert, argument count/length/NUL checks, optional per-command argument
// rules, a scrubbed environment (secrets are not inherited), a hard timeout and an output cap.
import { spawn } from "node:child_process";
import path from "node:path";

export interface CommandSpec {
  path: string; // absolute path to the binary
  description?: string; // shown to the agent by describePolicy()
  usage?: string; // e.g. "echo <text>"
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
  if (!path.isAbsolute(spec.path)) return Promise.reject(new ExecError("bad_policy", "command path must be absolute"));
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

// For agents: never throws, always the same JSON shape, and failures say what to do next.
const NEXT: Record<string, string> = {
  not_allowed: "Call describePolicy() to see which commands exist; this one is not available.",
  bad_args: "Check the usage line from describePolicy() and send fewer, shorter text arguments.",
  rejected_args: "The arguments broke this command's rules; see the message and follow its usage line.",
  bad_policy: "Ask the operator to fix the command policy; the agent cannot.",
  spawn_failed: "The program could not start on this machine; ask the operator.",
};
export interface ExecJson { ok: boolean; command: string; code: number | null; stdout: string; stderr: string; truncated: boolean; timedOut: boolean; ms: number; data?: unknown; error?: { class: string; message: string; next: string } }
export async function execJson(policy: ExecPolicy, name: string, args: string[] = []): Promise<ExecJson> {
  const t0 = Date.now(); const base = { command: String(name).slice(0, 40), ms: 0 };
  try {
    const r = await safeExec(policy, name, args); let data: unknown;
    if (r.code === 0 && /^\s*[[{]/.test(r.stdout)) { try { data = JSON.parse(r.stdout); } catch { /* plain text */ } }
    const ok = r.code === 0 && !r.timedOut && !r.truncated;
    return { ...base, ok, code: r.code, stdout: r.stdout, stderr: r.stderr, truncated: r.truncated, timedOut: r.timedOut, ms: Date.now() - t0, data,
      ...(ok ? {} : { error: { class: r.timedOut ? "timeout" : r.truncated ? "output_too_large" : "nonzero_exit", message: r.timedOut ? "the command ran too long and was stopped" : r.truncated ? "the output was cut at the size limit" : `the command exited with code ${r.code}`, next: r.timedOut ? "Try smaller input." : r.truncated ? "Ask for less output." : "Read stderr for the reason." } }) };
  } catch (e) {
    const code = e instanceof ExecError ? e.code : "error";
    return { ...base, ok: false, code: null, stdout: "", stderr: "", truncated: false, timedOut: false, ms: Date.now() - t0, error: { class: code, message: (e as Error).message.slice(0, 200), next: NEXT[code] ?? "Do not retry the same call." } };
  }
}
// Self-description an agent can read before calling (a tiny SKILL.md for the allowlist). Paths are not revealed.
export function describePolicy(policy: ExecPolicy): Array<{ name: string; description: string; usage: string; maxArgs: number }> {
  return Object.entries(policy.commands).map(([name, c]) => ({ name, description: c.description ?? "(no description)", usage: c.usage ?? name, maxArgs: c.maxArgs ?? 16 }));
}
