import { describe, expect, it } from "vitest";
import { githubRepo, readFeed } from "../src/safe-reach";
import { Deps } from "../src/safe-fetch";

const deps = (body: string, status = 200, seen: string[] = []): Deps => ({
  resolve: async () => ["140.82.112.5"],
  get: async ({ url, headers }) => { seen.push(url.toString() + "|" + (headers.Authorization ?? "")); return { status, headers: {}, body: Buffer.from(body) }; },
});

describe("githubRepo", () => {
  it("returns only the whitelisted fields", async () => {
    const r = await githubRepo("goodnight000", "api-anything", {}, deps(JSON.stringify({ full_name: "a/b", stargazers_count: 5, license: { spdx_id: "MIT" }, pushed_at: "2026-11-01", archived: false, default_branch: "main", secret: "x", owner: { email: "e" } })));
    expect(r).toEqual({ full_name: "a/b", stars: 5, license: "MIT", pushed_at: "2026-11-01", archived: false, default_branch: "main" });
  });
  it("rejects path-injection in owner/repo", async () => {
    for (const [o, r] of [["a/../b", "c"], ["a", "../../etc"], ["a b", "c"], ["a", ".."], ["", "c"]]) {
      await expect(githubRepo(o!, r!, {}, deps("{}"))).rejects.toThrow("invalid owner/repo");
    }
  });
  it("sends the token only to api.github.com", async () => {
    const seen: string[] = [];
    await githubRepo("a", "b", { token: "t0k" }, deps("{}", 200, seen)).catch(() => {});
    expect(seen[0]).toContain("https://api.github.com/repos/a/b|Bearer t0k");
  });
});

describe("readFeed", () => {
  const rss = `<rss><channel>
    <item><title><![CDATA[Hello <b>world</b>]]></title><link>https://x.com/1</link><pubDate>Mon, 09 Nov 2026</pubDate></item>
    <item><title>Bad</title><link>javascript:alert(1)</link></item>
  </channel></rss>`;
  it("parses items, strips markup and drops non-https links", async () => {
    const items = await readFeed("https://x.com/feed", ["x.com"], deps(rss));
    expect(items[0]).toMatchObject({ title: "Hello world", link: "https://x.com/1" });
    expect(items[1]!.link).toBe("");
  });
  it("refuses hosts outside the allowlist", async () => {
    await expect(readFeed("https://evil.com/feed", ["x.com"], deps(rss))).rejects.toThrow();
  });
});
