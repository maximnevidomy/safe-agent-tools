// approval-gate: nothing leaves (post, send, publish, pay) until a human approved THAT exact payload.
// An approval is an HMAC-signed, expiring, single-use token bound to a hash of the payload, so the payload
// cannot be swapped after approval, the token cannot be replayed, and a token minted elsewhere is rejected.
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export class GateError extends Error {
  constructor(public code: string, msg: string) { super(msg); }
}
const h = (s: string) => createHash("sha256").update(s).digest("hex");
const canon = (v: unknown): string =>
  Array.isArray(v) ? `[${v.map(canon).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v as object).sort().map((k) => JSON.stringify(k) + ":" + canon((v as Record<string, unknown>)[k])).join(",")}}`
  : JSON.stringify(v);

export interface Pending { id: string; action: string; payloadHash: string; summary: string; createdAt: number }

export class ApprovalGate {
  private pending = new Map<string, Pending>();
  private used = new Set<string>();
  constructor(private secret: string, private ttlMs = 10 * 60_000, private now: () => number = Date.now) {
    if (secret.length < 16) throw new GateError("weak_secret", "secret must be at least 16 characters");
  }
  private sign(body: string) { return createHmac("sha256", this.secret).update(body).digest("hex"); }

  // Agent side: ask for permission. Returns what the human will see.
  propose(action: string, payload: unknown, summary: string): Pending {
    const p: Pending = { id: randomBytes(12).toString("hex"), action, payloadHash: h(canon(payload)), summary: summary.slice(0, 500), createdAt: this.now() };
    this.pending.set(p.id, p);
    return p;
  }
  // Human side: only this call mints a token. Do not expose it to the agent.
  approve(id: string, approver: string): string {
    const p = this.pending.get(id);
    if (!p) throw new GateError("unknown_proposal", "no such proposal");
    this.pending.delete(id);
    const body = JSON.stringify({ id: p.id, a: p.action, ph: p.payloadHash, by: approver, exp: this.now() + this.ttlMs });
    return Buffer.from(body).toString("base64url") + "." + this.sign(body);
  }
  // Agent side: run the action only with a valid token for exactly this action + payload.
  async execute<T>(token: string, action: string, payload: unknown, run: () => Promise<T>): Promise<T> {
    const [b64, sig] = String(token).split(".");
    if (!b64 || !sig) throw new GateError("bad_token", "malformed token");
    const body = Buffer.from(b64, "base64url").toString("utf8");
    const want = Buffer.from(this.sign(body)), got = Buffer.from(sig);
    if (want.length !== got.length || !timingSafeEqual(want, got)) throw new GateError("bad_signature", "token not issued by this gate");
    const t = JSON.parse(body) as { id: string; a: string; ph: string; exp: number };
    if (this.now() > t.exp) throw new GateError("expired", "approval expired");
    if (t.a !== action) throw new GateError("wrong_action", "approval is for a different action");
    if (t.ph !== h(canon(payload))) throw new GateError("payload_changed", "payload differs from what was approved");
    if (this.used.has(t.id)) throw new GateError("replayed", "approval already used");
    this.used.add(t.id);
    return run();
  }
}
