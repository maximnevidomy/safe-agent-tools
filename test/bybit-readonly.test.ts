import { describe, expect, it } from "vitest";
import { ReadOnlyError, TOOLS, createClient } from "../src/bybit-readonly";

const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200 });
const fakeFetch = (log: Array<{ url: string; init: RequestInit }>, keyInfo: unknown = { readOnly: 1, permissions: { ContractTrade: [], Wallet: ["AccountTransfer"].slice(1) } }) =>
  (async (url: string, init: RequestInit) => {
    log.push({ url, init });
    if (url.includes("/v5/user/query-api")) return json({ retCode: 0, result: keyInfo });
    return json({ retCode: 0, result: { ok: true } });
  }) as unknown as typeof fetch;

describe("tool surface", () => {
  it("contains no write, key-management, transfer or withdraw endpoint", () => {
    const banned = /(create|cancel|amend|batch|withdraw|transfer|api-key|apikey|sub-member|set-|switch|leverage|trading-stop)/i;
    for (const t of TOOLS) expect(banned.test(t.path), t.path).toBe(false);
  });
  it("only reaches market data and read-only account paths", () => {
    for (const t of TOOLS) expect(t.path).toMatch(/^\/v5\/(market|position\/list|account\/wallet-balance|order\/realtime)/);
  });
  it("the list is frozen", () => {
    expect(Object.isFrozen(TOOLS)).toBe(true);
  });
});

describe("client", () => {
  it("defaults to testnet and refuses mainnet without explicit confirmation", () => {
    expect(createClient().network).toBe("testnet");
    expect(() => createClient({ network: "mainnet" })).toThrow(ReadOnlyError);
    expect(createClient({ network: "mainnet", confirmLive: true }).network).toBe("mainnet");
  });
  it("rejects unknown tools, including write-looking names", async () => {
    const c = createClient({ fetchImpl: fakeFetch([]) });
    for (const n of ["create_order", "withdraw", "create_api_key", "../v5/order/create"]) {
      await expect(c.call(n)).rejects.toBeInstanceOf(ReadOnlyError);
    }
  });
  it("only ever issues GET requests", async () => {
    const log: Array<{ url: string; init: RequestInit }> = [];
    const c = createClient({ apiKey: "k", apiSecret: "s", fetchImpl: fakeFetch(log) });
    await c.call("get_tickers", { category: "linear" });
    await c.call("get_positions", { category: "linear", settleCoin: "USDT" });
    expect(log.length).toBeGreaterThanOrEqual(3);
    expect(log.every((l) => l.init.method === "GET")).toBe(true);
    expect(log.every((l) => l.url.startsWith("https://api-testnet.bybit.com/"))).toBe(true);
  });
  it("signs private calls and does not sign public ones", async () => {
    const log: Array<{ url: string; init: RequestInit }> = [];
    const c = createClient({ apiKey: "k", apiSecret: "s", fetchImpl: fakeFetch(log), now: () => 1700000000000 });
    await c.call("get_tickers", { category: "spot" });
    const pub = log.at(-1)!.init.headers as Record<string, string>;
    expect(pub["X-BAPI-SIGN"]).toBeUndefined();
    await c.call("get_wallet_balance", { accountType: "UNIFIED" });
    const priv = log.at(-1)!.init.headers as Record<string, string>;
    expect(priv["X-BAPI-SIGN"]).toMatch(/^[0-9a-f]{64}$/);
  });
  it("refuses a key that can trade", async () => {
    const c = createClient({ apiKey: "k", apiSecret: "s", fetchImpl: fakeFetch([], { readOnly: 0, permissions: { ContractTrade: ["Order"] } }) });
    await expect(c.call("get_positions", { category: "linear" })).rejects.toThrow(/not read-only/);
  });
  it("refuses a read-only key that still has withdraw/transfer rights", async () => {
    const c = createClient({ apiKey: "k", apiSecret: "s", fetchImpl: fakeFetch([], { readOnly: 1, permissions: { Wallet: ["AccountTransfer"] } }) });
    await expect(c.call("get_wallet_balance", { accountType: "UNIFIED" })).rejects.toThrow(/not read-only/);
  });
  it("does not leak the secret in errors", async () => {
    const bad = (async () => new Response("x", { status: 500 })) as unknown as typeof fetch;
    const c = createClient({ fetchImpl: bad });
    await expect(c.call("get_tickers", {})).rejects.toThrow("Bybit HTTP 500");
  });
});
