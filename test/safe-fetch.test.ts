import { describe, expect, it } from "vitest";
import { Deps, RateLimiter, SafeFetchError, hostAllowed, isBlockedIp, safeFetch } from "../src/safe-fetch";

const opts = { allowHosts: ["api.example.com", "*.good.org"] };
const ok = (body = "ok") => ({ status: 200, headers: {}, body: Buffer.from(body) });
const mk = (map: Record<string, string[]>, get?: Deps["get"]): Deps => ({
  resolve: async (h) => map[h] ?? [],
  get: get ?? (async () => ok()),
});
const code = async (p: Promise<unknown>) => {
  try { await p; } catch (e) { return (e as SafeFetchError).code; }
  return "none";
};

describe("isBlockedIp", () => {
  it.each([
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::", "fc00::1", "fd12::1", "fe80::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "64:ff9b::7f00:1".replace("7f00:1", "127.0.0.1"),
  ])("blocks %s", (ip) => expect(isBlockedIp(ip)).toBe(true));
  it.each(["8.8.8.8", "93.184.216.34", "172.32.0.1", "2606:4700:4700::1111"])("allows %s", (ip) =>
    expect(isBlockedIp(ip)).toBe(false));
});

describe("hostAllowed", () => {
  it("matches exact and wildcard, not lookalikes", () => {
    expect(hostAllowed("api.example.com", opts.allowHosts)).toBe(true);
    expect(hostAllowed("x.good.org", opts.allowHosts)).toBe(true);
    expect(hostAllowed("good.org", opts.allowHosts)).toBe(false);
    expect(hostAllowed("evilgood.org", opts.allowHosts)).toBe(false);
    expect(hostAllowed("api.example.com.evil.io", opts.allowHosts)).toBe(false);
  });
});

describe("safeFetch", () => {
  it("fetches an allowed public host", async () => {
    const r = await safeFetch("https://api.example.com/x", opts, mk({ "api.example.com": ["93.184.216.34"] }));
    expect(r.status).toBe(200);
  });
  it("rejects empty allowlist, http, credentials, odd ports, unlisted hosts", async () => {
    const d = mk({ "api.example.com": ["93.184.216.34"] });
    expect(await code(safeFetch("https://api.example.com", { allowHosts: [] }, d))).toBe("no_allowlist");
    expect(await code(safeFetch("http://api.example.com", opts, d))).toBe("bad_scheme");
    expect(await code(safeFetch("https://u:p@api.example.com", opts, d))).toBe("bad_url");
    expect(await code(safeFetch("https://api.example.com:8443", opts, d))).toBe("bad_port");
    expect(await code(safeFetch("https://other.com", opts, d))).toBe("host_not_allowed");
  });
  it("rejects IP literals in every spelling", async () => {
    const d = mk({});
    for (const u of ["https://127.0.0.1", "https://2130706433", "https://0x7f.1", "https://[::1]", "https://169.254.169.254"]) {
      expect(["blocked_ip", "host_not_allowed"]).toContain(await code(safeFetch(u, { allowHosts: ["127.0.0.1", "[::1]", "169.254.169.254"] }, d)));
    }
  });
  it("rejects an allowed name that resolves to a private address, even if one record is public", async () => {
    expect(await code(safeFetch("https://api.example.com", opts, mk({ "api.example.com": ["10.0.0.5"] })))).toBe("blocked_ip");
    expect(await code(safeFetch("https://api.example.com", opts, mk({ "api.example.com": ["93.184.216.34", "127.0.0.1"] })))).toBe("blocked_ip");
  });
  it("pins the connection to the validated IP", async () => {
    let used = "";
    await safeFetch("https://api.example.com", opts, mk({ "api.example.com": ["93.184.216.34"] }, async ({ ip }) => { used = ip; return ok(); }));
    expect(used).toBe("93.184.216.34");
  });
  it("re-validates redirects (open redirect to metadata IP, to another host, to http)", async () => {
    const redirect = (to: string): Deps["get"] => async () => ({ status: 302, headers: { location: to }, body: Buffer.alloc(0) });
    const m = { "api.example.com": ["93.184.216.34"] };
    expect(await code(safeFetch("https://api.example.com", { allowHosts: ["api.example.com", "169.254.169.254"] }, mk(m, redirect("https://169.254.169.254/latest/meta-data/"))))).toBe("blocked_ip");
    expect(await code(safeFetch("https://api.example.com", opts, mk(m, redirect("https://evil.com/"))))).toBe("host_not_allowed");
    expect(await code(safeFetch("https://api.example.com", opts, mk(m, redirect("http://api.example.com/"))))).toBe("bad_scheme");
  });
  it("follows a safe redirect and caps redirect loops", async () => {
    let n = 0;
    const d = mk({ "api.example.com": ["93.184.216.34"] }, async () => (n++ === 0 ? { status: 301, headers: { location: "/next" }, body: Buffer.alloc(0) } : ok("done")));
    expect((await safeFetch("https://api.example.com", opts, d)).body.toString()).toBe("done");
    const loop = mk({ "api.example.com": ["93.184.216.34"] }, async () => ({ status: 302, headers: { location: "/again" }, body: Buffer.alloc(0) }));
    expect(await code(safeFetch("https://api.example.com", opts, loop))).toBe("too_many_redirects");
  });
});

describe("RateLimiter", () => {
  it("allows a burst then throttles, then refills", () => {
    let t = 0;
    const rl = new RateLimiter(2, 1, () => t);
    expect([rl.allow("a"), rl.allow("a"), rl.allow("a")]).toEqual([true, true, false]);
    expect(rl.allow("b")).toBe(true);
    t = 1500;
    expect(rl.allow("a")).toBe(true);
  });
});
