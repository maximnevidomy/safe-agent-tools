import { describe, expect, it } from "vitest";
import { readPage, htmlToText } from "../src/read-page";
import { channelUrl, readChannel } from "../src/safe-reach";
import type { Deps } from "../src/safe-fetch";

const mk = (body: string, ct = "text/html"): Deps => ({ resolve: async () => ["93.184.216.34"], get: async () => ({ status: 200, headers: { "content-type": ct }, body: Buffer.from(body) }) });

describe("read-page", () => {
  const html = `<html><head><title>Hi &amp; bye</title><style>x{}</style><script>steal()</script></head><body><nav>menu</nav><h1>Hello</h1><p>World &lt;b&gt;</p><a href="/a">Local</a><a href="http://plain.example/x">plain</a><a href="javascript:alert(1)">js</a><a href="https://u:p@evil.example/">cred</a><a href="https://ok.example/y">Good</a></body></html>`;
  it("extracts text, drops scripts and keeps only safe https links", () => {
    const r = htmlToText(html, "https://site.example/page");
    expect(r.title).toBe("Hi & bye"); expect(r.text).toContain("Hello"); expect(r.text).toContain("World <b>");
    expect(r.text).not.toContain("steal"); expect(r.text).not.toContain("menu");
    expect(r.links.map((l) => l.url)).toEqual(["https://site.example/a", "https://ok.example/y"]);
  });
  it("truncates long pages and refuses non-text and private targets", async () => {
    expect(htmlToText("<p>" + "a".repeat(9000) + "</p>", "https://s.example/").truncated).toBe(true);
    await expect(readPage("https://s.example/", mk("%PDF", "application/pdf"))).rejects.toThrow(/not a text page/);
    await expect(readPage("https://localhost/admin", mk(""))).rejects.toThrow();
    await expect(readPage("https://169.254.169.254/latest", mk(""))).rejects.toThrow(/private|reserved/);
    await expect(readPage("http://s.example/", mk(""))).rejects.toThrow(/https/);
    expect((await readPage("https://s.example/", mk(html))).title).toBe("Hi & bye");
  });
});

describe("channels", () => {
  it("builds fixed-host urls and rejects tricks", () => {
    expect(channelUrl("youtube", "UCBR8-60-B28hp2BmDPdntcQ").host).toBe("www.youtube.com");
    expect(channelUrl("github-releases", "a/b").url).toBe("https://github.com/a/b/releases.atom");
    expect(channelUrl("reddit", "programming").host).toBe("www.reddit.com");
    expect(() => channelUrl("reddit", "../x")).toThrow(/invalid/);
    expect(() => channelUrl("youtube", "UC123")).toThrow(/invalid/);
    expect(() => channelUrl("github-releases", "../../x")).toThrow(/invalid/);
  });
  it("reads a feed and drops unsafe links", async () => {
    const xml = `<feed><entry><title>v1</title><link href="https://github.com/a/b/releases/tag/v1"/><updated>2026-01-01</updated></entry><entry><title>bad</title><link href="javascript:x"/></entry></feed>`;
    const r = await readChannel("github-releases", "a/b", mk(xml, "application/atom+xml"));
    expect(r[0]!.link).toContain("https://github.com"); expect(r[1]!.link).toBe("");
  });
});
