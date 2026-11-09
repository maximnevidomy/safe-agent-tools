import { describe, expect, it } from "vitest";
import { checkSite, serviceRoleTokens } from "../src/site-check";
import type { Deps } from "../src/safe-fetch";

const jwt = (role: string) => `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ role })).toString("base64url")}.abcdefghijk`;
const site = (over: { headers?: Record<string, string | string[]>; html?: string; env?: string; js?: string; map?: boolean } = {}): Deps => ({
  resolve: async () => ["93.184.216.34"],
  get: async ({ url }) => {
    const ok = (body: string, headers: Record<string, string | string[]> = {}) => ({ status: 200, headers, body: Buffer.from(body) });
    const nf = { status: 404, headers: {}, body: Buffer.from("no") };
    if (url.pathname === "/.env") return over.env ? ok(over.env, { "content-type": "text/plain" }) : nf;
    if (url.pathname === "/app.js") return ok(over.js ?? "console.log(1)");
    if (url.pathname === "/app.js.map") return over.map ? ok('{"version":3,"sources":["a.ts"]}') : nf;
    if (url.pathname === "/robots.txt") return ok("User-agent: *");
    if (url.pathname === "/sitemap.xml") return ok("<urlset></urlset>");
    if (url.pathname === "/") return ok(over.html ?? '<html lang="en"><head><title>T</title><meta name="description" content="A long enough description of the page"><meta name="viewport" content="width=device-width"><meta property="og:title" content="x"><link rel="icon" href="/f.ico"></head><body><a href="/privacy">Privacy</a><script src="/app.js"></script></body></html>', over.headers ?? { "strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer" });
    return nf;
  },
});
const rules = async (d: Deps) => (await checkSite("https://s.example/", d)).findings.map((f) => f.rule);

describe("site-check", () => {
  it("a well configured site passes both scores", async () => {
    const r = await checkSite("https://s.example/", site()); expect(r.verdict).toBe("launch"); expect(r.security).toBe(100); expect(r.readiness).toBe(100);
  });
  it("flags missing headers, bad cookies, open CORS", async () => {
    const r = await rules(site({ headers: { "set-cookie": ["session=abc; Path=/"], "access-control-allow-origin": "*", "x-powered-by": "Express 4.1" } }));
    expect(r).toEqual(expect.arrayContaining(["no-hsts", "no-csp", "clickjacking", "cookie-flags", "open-cors", "version-leak"]));
  });
  it("finds an exposed .env but not an html page answering 200", async () => {
    expect(await rules(site({ env: "DB_PASSWORD=hunter2\nAPI_KEY=abc" }))).toContain("exposed-env");
    expect(await rules(site({ env: "<html><body>hello</body></html>" }))).not.toContain("exposed-env");
  });
  it("finds a service_role key and a public source map in scripts", async () => {
    const r = await rules(site({ js: `const k="${jwt("service_role")}";\n//# sourceMappingURL=app.js.map`, map: true }));
    expect(r).toContain("service-role-key"); expect(r).toContain("source-map");
    expect(await rules(site({ js: `const k="${jwt("anon")}"` }))).not.toContain("service-role-key");
  });
  it("flags missing launch basics", async () => {
    const r = await rules(site({ html: "<html><body>hi</body></html>" }));
    expect(r).toEqual(expect.arrayContaining(["no-title", "no-description", "no-viewport", "no-legal"]));
  });
  it("jwt detector ignores junk", () => { expect(serviceRoleTokens("eyJabc.eyJdef.ghi")).toBe(0); expect(serviceRoleTokens(jwt("service_role"))).toBe(1); });
  it("refuses private targets", async () => {
    await expect(checkSite("https://localhost/", site())).rejects.toThrow();
    await expect(checkSite("http://s.example/", site())).rejects.toThrow(/https/);
  });
});
