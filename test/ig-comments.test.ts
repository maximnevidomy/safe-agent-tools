import { describe, expect, it } from "vitest";
import { handleCommentEvent, resolveTracked, trackedLink, type CommentDeps } from "../src/ig-webhook";

const ev = (text: string, o: { id?: string; from?: string; media?: string; username?: string } = {}) => ({ entry: [{ changes: [{ field: "comments", value: { id: o.id ?? "17900_1", text, from: { id: o.from ?? "555555", username: o.username ?? "dana.s" }, media: { id: o.media ?? "M1" } } }] }] });
const mk = (over: Partial<CommentDeps> = {}) => {
  const seen = new Set<string>(), opted = new Set<string>(), dms: string[] = [], pub: string[] = [];
  const d: CommentDeps = { store: { isOptedOut: async (s) => opted.has(s), setOptedOut: async () => {}, isHandedOver: async () => false, seen: async (m) => (seen.has(m) ? true : (seen.add(m), false)) },
    campaigns: [{ id: "guide", keyword: "guide", mediaId: "M1", dm: "Hi {username}, here: {link}", publicReply: "Sent!" }], selfId: "999999",
    privateReply: async (_c, t) => void dms.push(t), publicReply: async (_c, t) => void pub.push(t), allow: () => true, link: (c, u) => `https://t.example/r/${c}.${u}`, ...over };
  return { d, dms, pub, opted };
};

describe("comment to DM", () => {
  it("replies privately with the name and a tracked link, and answers publicly", async () => {
    const { d, dms, pub } = mk();
    expect(await handleCommentEvent(ev("send me the GUIDE please"), d)).toEqual(["dm_sent"]);
    expect(dms[0]).toBe("Hi dana.s, here: https://t.example/r/guide.555555"); expect(pub).toEqual(["Sent!"]);
  });
  it("ignores other posts, our own comments, junk and unknown keywords", async () => {
    const { d } = mk();
    expect(await handleCommentEvent(ev("guide", { media: "OTHER" }), d)).toEqual(["no_campaign"]);
    expect(await handleCommentEvent(ev("guide", { from: "999999" }), d)).toEqual(["skipped_self"]);
    expect(await handleCommentEvent(ev("nice photo"), d)).toEqual(["no_campaign"]);
    expect(await handleCommentEvent({ entry: [{ changes: [{ field: "comments", value: { id: "x", text: 5 } }] }] }, d)).toEqual(["ignored"]);
    expect(await handleCommentEvent("nope", d)).toEqual([]);
  });
  it("answers each person once per campaign and each comment once", async () => {
    const { d, dms } = mk();
    await handleCommentEvent(ev("guide", { id: "111_1" }), d);
    expect(await handleCommentEvent(ev("guide", { id: "111_1" }), d)).toEqual(["skipped_duplicate"]);
    expect(await handleCommentEvent(ev("guide again", { id: "111_2" }), d)).toEqual(["skipped_duplicate"]);
    expect(dms.length).toBe(1);
  });
  it("respects opt-out, rate limit and the follow gate", async () => {
    const a = mk(); a.opted.add("555555"); expect(await handleCommentEvent(ev("guide"), a.d)).toEqual(["skipped_optout"]); expect(a.dms).toEqual([]);
    const b = mk({ allow: () => false }); expect(await handleCommentEvent(ev("guide"), b.d)).toEqual(["skipped_ratelimit"]);
    const c = mk({ isFollower: async () => false, campaigns: [{ id: "g", keyword: "guide", dm: "secret link", requireFollow: true, followPrompt: "Follow first" }] });
    expect(await handleCommentEvent(ev("guide"), c.d)).toEqual(["needs_follow"]); expect(c.dms).toEqual(["Follow first"]);
  });
  it("drops a hostile username instead of sending it", async () => {
    const { d, dms } = mk(); await handleCommentEvent(ev("guide", { username: "<script>x</script>" }), d);
    expect(dms[0]).not.toContain("<");
  });
});

describe("tracked links", () => {
  const targets = { guide: "https://shop.example/guide" };
  it("resolves a signed link to a fixed target, rejects tampering and unknown campaigns", () => {
    const u = new URL(trackedLink("https://t.example", "s3cret", "guide", "555555"));
    expect(resolveTracked(u.pathname, "s3cret", targets)).toEqual({ campaignId: "guide", userId: "555555", to: "https://shop.example/guide" });
    expect(resolveTracked(u.pathname, "other", targets)).toBeNull();
    expect(resolveTracked(u.pathname.replace("555555", "555556"), "s3cret", targets)).toBeNull();
    const evil = new URL(trackedLink("https://t.example", "s3cret", "evil", "555555"));
    expect(resolveTracked(evil.pathname, "s3cret", targets)).toBeNull();
    expect(resolveTracked(u.pathname, "s3cret", { guide: "http://plain.example" })).toBeNull();
  });
});
