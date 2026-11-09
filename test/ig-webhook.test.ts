import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Deps, handleEvent, verifyChallenge, verifySignature } from "../src/ig-webhook";
import { RateLimiter } from "../src/safe-fetch";

const secret = "app-secret";
const sign = (b: string, s = secret) => "sha256=" + createHmac("sha256", s).update(b).digest("hex");

describe("verifySignature", () => {
  const body = '{"entry":[]}';
  it("accepts a correct signature", () => expect(verifySignature(body, sign(body), secret)).toBe(true));
  it("rejects wrong secret, tampered body, missing/garbled headers, empty secret", () => {
    expect(verifySignature(body, sign(body, "other"), secret)).toBe(false);
    expect(verifySignature(body + " ", sign(body), secret)).toBe(false);
    expect(verifySignature(body, undefined, secret)).toBe(false);
    expect(verifySignature(body, "sha256=zz", secret)).toBe(false);
    expect(verifySignature(body, "sha1=" + "a".repeat(40), secret)).toBe(false);
    expect(verifySignature(body, sign(body, ""), "")).toBe(false);
  });
});

describe("verifyChallenge", () => {
  const q = (o: Record<string, string>) => ({ "hub.mode": "subscribe", "hub.verify_token": "tok", "hub.challenge": "12345", ...o });
  it("echoes the challenge only for the right token", () => {
    expect(verifyChallenge(q({}), "tok")).toBe("12345");
    expect(verifyChallenge(q({ "hub.verify_token": "bad" }), "tok")).toBeNull();
    expect(verifyChallenge(q({ "hub.mode": "other" }), "tok")).toBeNull();
    expect(verifyChallenge(q({}), "")).toBeNull();
  });
  it("refuses a challenge that could carry markup", () => {
    expect(verifyChallenge(q({ "hub.challenge": "<script>x</script>" }), "tok")).toBeNull();
  });
});

function setup() {
  const sent: Array<[string, string]> = [];
  const opted = new Set<string>(), hand = new Set<string>(), seen = new Set<string>();
  const d: Deps = {
    store: {
      isOptedOut: async (s) => opted.has(s),
      setOptedOut: async (s, v) => void (v ? opted.add(s) : opted.delete(s)),
      isHandedOver: async (s) => hand.has(s),
      seen: async (m) => (seen.has(m) ? true : (seen.add(m), false)),
    },
    rules: [{ keywords: ["מחיר", "price"], reply: "329 לחודש" }],
    send: async (r, t) => void sent.push([r, t]),
    allow: () => true,
  };
  return { d, sent, opted, hand };
}
const ev = (sid: string, mid: string, text: string, extra: object = {}) => ({ entry: [{ messaging: [{ sender: { id: sid }, message: { mid, text, ...extra } }] }] });

describe("handleEvent", () => {
  it("replies to a matching keyword", async () => {
    const { d, sent } = setup();
    expect(await handleEvent(ev("11111", "m1", "מה המחיר?"), d)).toEqual(["replied"]);
    expect(sent).toEqual([["11111", "329 לחודש"]]);
  });
  it("drops replays of the same message id", async () => {
    const { d, sent } = setup();
    await handleEvent(ev("11111", "m1", "price"), d);
    expect(await handleEvent(ev("11111", "m1", "price"), d)).toEqual(["skipped_duplicate"]);
    expect(sent).toHaveLength(1);
  });
  it("honours stop, stays silent afterwards, and resumes on start", async () => {
    const { d, sent } = setup();
    expect(await handleEvent(ev("11111", "m1", "הסר"), d)).toEqual(["opted_out"]);
    expect(await handleEvent(ev("11111", "m2", "price"), d)).toEqual(["skipped_optout"]);
    expect(sent).toHaveLength(1); // only the confirmation
    expect(await handleEvent(ev("11111", "m3", "הרשם"), d)).toEqual(["opted_in"]);
    expect(await handleEvent(ev("11111", "m4", "price"), d)).toEqual(["replied"]);
  });
  it("stays silent when a human has taken over", async () => {
    const { d, sent, hand } = setup();
    hand.add("11111");
    expect(await handleEvent(ev("11111", "m1", "price"), d)).toEqual(["skipped_handover"]);
    expect(sent).toHaveLength(0);
  });
  it("rate-limits one sender without affecting another", async () => {
    const { d } = setup();
    const rl = new RateLimiter(1, 0.001);
    d.allow = (s) => rl.allow(s);
    expect(await handleEvent(ev("11111", "a", "price"), d)).toEqual(["replied"]);
    expect(await handleEvent(ev("11111", "b", "price"), d)).toEqual(["skipped_ratelimit"]);
    expect(await handleEvent(ev("22222", "c", "price"), d)).toEqual(["replied"]);
  });
  it("ignores echoes, junk, malformed ids and odd payload shapes without throwing", async () => {
    const { d, sent } = setup();
    expect(await handleEvent(ev("11111", "m1", "price", { is_echo: true }), d)).toEqual(["ignored"]);
    expect(await handleEvent(ev("../../x", "m2", "price"), d)).toEqual(["ignored"]);
    expect(await handleEvent({ entry: [{ messaging: [{ message: { text: 5 } }] }] }, d)).toEqual(["ignored"]);
    for (const junk of [null, undefined, 5, "x", [], { entry: "x" }]) expect(await handleEvent(junk, d)).toEqual([]);
    expect(sent).toHaveLength(0);
  });
  it("never writes message text into the store", async () => {
    const { d } = setup();
    const written: string[] = [];
    const orig = d.store.seen;
    d.store.seen = async (m) => (written.push(m), orig(m));
    await handleEvent(ev("11111", "mid-1", "my secret question about price"), d);
    expect(JSON.stringify(written)).not.toContain("secret question");
  });
});
