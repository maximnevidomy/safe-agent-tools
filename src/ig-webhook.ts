// ig-webhook: the security core of an Instagram DM auto-reply bot built on the OFFICIAL Meta API.
// Verifies Meta's HMAC signature on the raw body, answers the subscribe challenge with a constant-time
// token check, drops replays, rate-limits per sender, honours opt-out ("stop") and human handover, and
// never stores message text.
import { createHmac, timingSafeEqual } from "node:crypto";

const safeEq = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

// Header looks like "sha256=<hex>". Must be computed over the RAW request bytes, before JSON parsing.
export function verifySignature(rawBody: Buffer | string, header: string | undefined, appSecret: string): boolean {
  if (!header || !appSecret) return false;
  const m = /^sha256=([0-9a-f]{64})$/i.exec(header.trim());
  if (!m) return false;
  const expected = createHmac("sha256", appSecret).update(rawBody).digest("hex");
  return safeEq(expected, m[1]!.toLowerCase());
}

// GET subscription handshake. Returns the challenge to echo, or null to answer 403.
export function verifyChallenge(q: Record<string, string | undefined>, verifyToken: string): string | null {
  if (q["hub.mode"] !== "subscribe" || !verifyToken) return null;
  if (!q["hub.verify_token"] || !safeEq(q["hub.verify_token"], verifyToken)) return null;
  const c = q["hub.challenge"];
  return c && /^[A-Za-z0-9_-]{1,64}$/.test(c) ? c : null; // numeric/opaque only: no reflected markup
}

export interface Store {
  // Holds ids only, never message content.
  isOptedOut(senderId: string): Promise<boolean>;
  setOptedOut(senderId: string, v: boolean): Promise<void>;
  isHandedOver(senderId: string): Promise<boolean>;
  seen(messageId: string): Promise<boolean>; // returns true if already processed, records it otherwise
}
export interface Rule { keywords: string[]; reply: string }
export interface Deps {
  store: Store;
  rules: Rule[];
  send(recipientId: string, text: string): Promise<void>;
  allow(senderId: string): boolean; // rate limiter hook
}

const STOP = ["stop", "unsubscribe", "הסר", "הסירו", "הפסק", "הפסיקו", "ביטול"];
const START = ["start", "subscribe", "הרשם", "חזור"];
const norm = (s: string) => s.trim().toLowerCase().replace(/[.!?,]+$/g, "");

export type Outcome = "replied" | "opted_out" | "opted_in" | "skipped_optout" | "skipped_handover" | "skipped_duplicate" | "skipped_ratelimit" | "no_rule" | "ignored";

interface MsgEvent { sender?: { id?: string }; message?: { mid?: string; text?: string; is_echo?: boolean } }

export async function handleEvent(body: unknown, d: Deps): Promise<Outcome[]> {
  const out: Outcome[] = [];
  const entries = (body as { entry?: Array<{ messaging?: MsgEvent[] }> })?.entry;
  if (!Array.isArray(entries)) return out;
  for (const e of entries.slice(0, 50)) {
    for (const ev of (e.messaging ?? []).slice(0, 50)) {
      const sid = ev.sender?.id, mid = ev.message?.mid, text = ev.message?.text;
      if (!sid || !/^\d{5,20}$/.test(sid) || !mid || typeof text !== "string" || ev.message?.is_echo) { out.push("ignored"); continue; }
      if (await d.store.seen(mid)) { out.push("skipped_duplicate"); continue; }
      const t = norm(text.slice(0, 200));
      if (STOP.includes(t)) {
        await d.store.setOptedOut(sid, true);
        await d.send(sid, "הוסרת מההודעות האוטומטיות. כתבי 'הרשם' כדי לחזור.");
        out.push("opted_out"); continue;
      }
      if (START.includes(t)) {
        await d.store.setOptedOut(sid, false);
        await d.send(sid, "נרשמת מחדש להודעות.");
        out.push("opted_in"); continue;
      }
      if (await d.store.isOptedOut(sid)) { out.push("skipped_optout"); continue; }
      if (await d.store.isHandedOver(sid)) { out.push("skipped_handover"); continue; } // a human is answering
      if (!d.allow(sid)) { out.push("skipped_ratelimit"); continue; }
      const rule = d.rules.find((r) => r.keywords.some((k) => t.includes(k.toLowerCase())));
      if (!rule) { out.push("no_rule"); continue; }
      await d.send(sid, rule.reply);
      out.push("replied");
    }
  }
  return out;
}

// ---- Comment-to-DM (the InstaMation feature): a keyword in a comment on a chosen post triggers a private reply. ----
// Same guarantees as the message path: signature is verified by the caller, replays and repeat commenters are dropped,
// opted-out people are skipped, rate-limited, and the comment text is never stored. Official "private replies" only.
export interface Campaign { id: string; keyword: string; mediaId?: string; dm: string; publicReply?: string; requireFollow?: boolean; followPrompt?: string }
export interface CommentDeps {
  store: Store;
  campaigns: Campaign[];
  selfId: string; // our own account: never answer our own comments
  privateReply(commentId: string, text: string): Promise<void>;
  publicReply?(commentId: string, text: string): Promise<void>;
  isFollower?(userId: string): Promise<boolean>;
  allow(senderId: string): boolean;
  link?(campaignId: string, userId: string): string; // tracked link inserted for {link}
}
export type CommentOutcome = "dm_sent" | "needs_follow" | "skipped_duplicate" | "skipped_optout" | "skipped_ratelimit" | "skipped_self" | "no_campaign" | "ignored";
interface CommentChange { field?: string; value?: { id?: string; text?: string; from?: { id?: string; username?: string }; media?: { id?: string } } }

const fill = (tpl: string, vars: { username?: string; link?: string }) =>
  tpl.replace(/\{username\}/g, vars.username && /^[A-Za-z0-9._]{1,30}$/.test(vars.username) ? vars.username : "").replace(/\{link\}/g, vars.link ?? "").replace(/\s{2,}/g, " ").trim();

export async function handleCommentEvent(body: unknown, d: CommentDeps): Promise<CommentOutcome[]> {
  const out: CommentOutcome[] = [];
  const entries = (body as { entry?: Array<{ changes?: CommentChange[] }> })?.entry;
  if (!Array.isArray(entries)) return out;
  for (const e of entries.slice(0, 50)) {
    for (const ch of (e.changes ?? []).slice(0, 50)) {
      const v = ch.value, uid = v?.from?.id, cid = v?.id, text = v?.text;
      if (ch.field !== "comments" || !uid || !/^\d{5,20}$/.test(uid) || !cid || !/^[\d_]{5,40}$/.test(cid) || typeof text !== "string") { out.push("ignored"); continue; }
      if (uid === d.selfId) { out.push("skipped_self"); continue; }
      const t = norm(text.slice(0, 300));
      const camp = d.campaigns.find((c) => (!c.mediaId || c.mediaId === v?.media?.id) && t.includes(c.keyword.toLowerCase()));
      if (!camp) { out.push("no_campaign"); continue; }
      if (await d.store.seen(`comment:${cid}`) || await d.store.seen(`once:${camp.id}:${uid}`)) { out.push("skipped_duplicate"); continue; }
      if (await d.store.isOptedOut(uid)) { out.push("skipped_optout"); continue; }
      if (!d.allow(uid)) { out.push("skipped_ratelimit"); continue; }
      if (camp.requireFollow && d.isFollower && !(await d.isFollower(uid))) {
        await d.privateReply(cid, camp.followPrompt ?? "Follow us first, then comment again and the link is yours.");
        out.push("needs_follow"); continue;
      }
      await d.privateReply(cid, fill(camp.dm, { username: v?.from?.username, link: d.link?.(camp.id, uid) }));
      if (camp.publicReply && d.publicReply) await d.publicReply(cid, camp.publicReply);
      out.push("dm_sent");
    }
  }
  return out;
}

// ---- Tracked links: click counts per campaign without an open redirect. ----
// The link carries the campaign, the person and a signature. The redirect target is looked up server side from a fixed table,
// never taken from the URL, so the tracker cannot be abused to send people to arbitrary sites.
export function trackedLink(base: string, secret: string, campaignId: string, userId: string): string {
  const p = `${campaignId}.${userId}`;
  return `${base.replace(/\/$/, "")}/r/${p}.${createHmac("sha256", secret).update(p).digest("hex").slice(0, 24)}`;
}
export function resolveTracked(pathname: string, secret: string, targets: Record<string, string>): { campaignId: string; userId: string; to: string } | null {
  const m = /^\/r\/([A-Za-z0-9_-]{1,40})\.(\d{5,20})\.([0-9a-f]{24})$/.exec(pathname);
  if (!m) return null;
  const want = createHmac("sha256", secret).update(`${m[1]}.${m[2]}`).digest("hex").slice(0, 24);
  const to = Object.prototype.hasOwnProperty.call(targets, m[1]!) ? targets[m[1]!]! : "";
  return safeEq(want, m[3]!) && /^https:\/\//.test(to) ? { campaignId: m[1]!, userId: m[2]!, to } : null;
}
