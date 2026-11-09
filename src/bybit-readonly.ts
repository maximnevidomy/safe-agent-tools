// bybit-readonly: a Bybit V5 client that can only READ. There is no POST code path at all, only an
// allowlist of GET endpoints. Testnet by default; mainnet needs an explicit double opt-in. Keys that
// carry trade/withdraw permissions are refused at startup, so a leaked key cannot do damage via this tool.
import { createHmac } from "node:crypto";

export type Network = "testnet" | "mainnet";
const BASE: Record<Network, string> = { testnet: "https://api-testnet.bybit.com", mainnet: "https://api.bybit.com" };

export interface ToolDef { name: string; description: string; path: string; auth: boolean }
// The ONLY endpoints this client can reach. Adding a write endpoint here must fail the test suite.
export const TOOLS: readonly ToolDef[] = Object.freeze([
  { name: "get_tickers", description: "Latest price and 24h stats", path: "/v5/market/tickers", auth: false },
  { name: "get_kline", description: "Candles", path: "/v5/market/kline", auth: false },
  { name: "get_orderbook", description: "Order book depth", path: "/v5/market/orderbook", auth: false },
  { name: "get_funding_history", description: "Funding rate history", path: "/v5/market/funding/history", auth: false },
  { name: "get_recent_trades", description: "Latest public trades", path: "/v5/market/recent-trade", auth: false },
  { name: "get_open_interest", description: "Open interest history", path: "/v5/market/open-interest", auth: false },
  { name: "get_long_short_ratio", description: "Buy/sell account ratio", path: "/v5/market/account-ratio", auth: false },
  { name: "get_instruments_info", description: "Contract and coin specifications", path: "/v5/market/instruments-info", auth: false },
  { name: "get_risk_limit", description: "Risk limit tiers", path: "/v5/market/risk-limit", auth: false },
  { name: "get_insurance_pool", description: "Insurance pool balance", path: "/v5/market/insurance", auth: false },
  { name: "get_historical_volatility", description: "Options historical volatility", path: "/v5/market/historical-volatility", auth: false },
  { name: "get_fee_rate", description: "Trading fee rate (read)", path: "/v5/account/fee-rate", auth: true },
  { name: "get_closed_pnl", description: "Closed profit and loss (read)", path: "/v5/position/closed-pnl", auth: true },
  { name: "get_executions", description: "Trade executions (read)", path: "/v5/execution/list", auth: true },
  { name: "get_transaction_log", description: "Account transaction log (read)", path: "/v5/account/transaction-log", auth: true },
  { name: "get_positions", description: "Open positions (read)", path: "/v5/position/list", auth: true },
  { name: "get_wallet_balance", description: "Wallet balance (read)", path: "/v5/account/wallet-balance", auth: true },
  { name: "get_open_orders", description: "Open orders (read)", path: "/v5/order/realtime", auth: true },
]);
const KEY_CHECK_PATH = "/v5/user/query-api";

export interface Options {
  apiKey?: string;
  apiSecret?: string;
  network?: Network;
  confirmLive?: boolean; // required together with network "mainnet"
  fetchImpl?: typeof fetch;
  now?: () => number;
  recvWindow?: number;
}

export class ReadOnlyError extends Error {}

export function createClient(o: Options = {}) {
  const network = o.network ?? "testnet";
  if (network === "mainnet" && o.confirmLive !== true) {
    throw new ReadOnlyError('mainnet requires confirmLive: true (testnet is the default)');
  }
  const f = o.fetchImpl ?? fetch;
  const now = o.now ?? Date.now;
  const recv = String(o.recvWindow ?? 5000);
  let keyChecked = false;

  async function rawGet(path: string, params: Record<string, string | number>, signed: boolean) {
    const qs = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString();
    const headers: Record<string, string> = {};
    if (signed) {
      if (!o.apiKey || !o.apiSecret) throw new ReadOnlyError("this tool needs apiKey and apiSecret");
      const ts = String(now());
      headers["X-BAPI-API-KEY"] = o.apiKey;
      headers["X-BAPI-TIMESTAMP"] = ts;
      headers["X-BAPI-RECV-WINDOW"] = recv;
      headers["X-BAPI-SIGN"] = createHmac("sha256", o.apiSecret).update(ts + o.apiKey + recv + qs).digest("hex");
    }
    const res = await f(`${BASE[network]}${path}${qs ? "?" + qs : ""}`, { method: "GET", headers, redirect: "error" });
    if (!res.ok) throw new Error(`Bybit HTTP ${res.status}`);
    return (await res.json()) as { retCode: number; retMsg: string; result: any };
  }

  // Refuse keys that can trade or withdraw. Bybit reports readOnly=1 for read-only keys.
  async function assertKeyReadOnly() {
    const r = await rawGet(KEY_CHECK_PATH, {}, true);
    const info = r.result ?? {};
    const perms = info.permissions ?? {};
    const wallet: string[] = Array.isArray(perms.Wallet) ? perms.Wallet : [];
    if (r.retCode !== 0 || info.readOnly !== 1 || wallet.includes("Withdraw") || wallet.includes("AccountTransfer")) {
      throw new ReadOnlyError("API key is not read-only (trade/withdraw/transfer permission present). Create a read-only key.");
    }
    keyChecked = true;
  }

  async function call(name: string, params: Record<string, string | number> = {}) {
    const tool = TOOLS.find((t) => t.name === name);
    if (!tool) throw new ReadOnlyError(`unknown or forbidden tool: ${name}`);
    if (tool.auth && !keyChecked) await assertKeyReadOnly();
    const r = await rawGet(tool.path, params, tool.auth);
    if (r.retCode !== 0) throw new Error(`Bybit error ${r.retCode}`); // never echo retMsg blindly
    return r.result;
  }

  return { network, tools: TOOLS, call, assertKeyReadOnly };
}
