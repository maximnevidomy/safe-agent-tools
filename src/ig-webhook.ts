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
