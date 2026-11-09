import { describe, expect, it } from "vitest";
import { ApprovalGate, GateError } from "../src/approval-gate";

const SECRET = "a-long-enough-secret-value";
const code = async (p: Promise<unknown>) => { try { await p; } catch (e) { return (e as GateError).code; } return "none"; };

describe("ApprovalGate", () => {
  it("runs the action once after approval", async () => {
    const g = new ApprovalGate(SECRET);
    const payload = { to: "page", text: "hello" };
    const p = g.propose("post", payload, "Post hello to page");
    const tok = g.approve(p.id, "maxim");
    let ran = 0;
    expect(await g.execute(tok, "post", payload, async () => ++ran)).toBe(1);
    expect(ran).toBe(1);
  });
  it("rejects a swapped payload (even with the keys in a different order it is still the same payload)", async () => {
    const g = new ApprovalGate(SECRET);
    const p = g.propose("post", { a: 1, b: 2 }, "s");
    const tok = g.approve(p.id, "m");
    expect(await code(g.execute(tok, "post", { a: 1, b: 3 }, async () => 1))).toBe("payload_changed");
    const p2 = g.propose("post", { a: 1, b: 2 }, "s");
    const tok2 = g.approve(p2.id, "m");
    expect(await g.execute(tok2, "post", { b: 2, a: 1 }, async () => "ok")).toBe("ok");
  });
  it("rejects replay, wrong action, expiry, forged and malformed tokens", async () => {
    let t = 0;
    const g = new ApprovalGate(SECRET, 1000, () => t);
    const payload = { x: 1 };
    const tok = g.approve(g.propose("send", payload, "s").id, "m");
    await g.execute(tok, "send", payload, async () => 1);
    expect(await code(g.execute(tok, "send", payload, async () => 1))).toBe("replayed");
    const tok2 = g.approve(g.propose("send", payload, "s").id, "m");
    expect(await code(g.execute(tok2, "delete", payload, async () => 1))).toBe("wrong_action");
    const tok3 = g.approve(g.propose("send", payload, "s").id, "m");
    t = 5000;
    expect(await code(g.execute(tok3, "send", payload, async () => 1))).toBe("expired");
    const other = new ApprovalGate("another-long-secret-value!");
    const forged = other.approve(other.propose("send", payload, "s").id, "m");
    t = 0;
    expect(await code(g.execute(forged, "send", payload, async () => 1))).toBe("bad_signature");
    expect(await code(g.execute("garbage", "send", payload, async () => 1))).toBe("bad_token");
  });
  it("agent cannot execute without ever being approved, and weak secrets are refused", async () => {
    const g = new ApprovalGate(SECRET);
    g.propose("post", { a: 1 }, "s");
    expect(await code(g.execute("", "post", { a: 1 }, async () => 1))).toBe("bad_token");
    expect(() => new ApprovalGate("short")).toThrow();
    expect(() => g.approve("nope", "m")).toThrow();
  });
});
