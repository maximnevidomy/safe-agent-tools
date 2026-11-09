import { describe, expect, it } from "vitest";
import { extractPrice } from "../src/price-extract";
import { SafeFetchError, safeFetch, type Deps } from "../src/safe-fetch";

const U = "https://shop.example/p/1";
describe("extractPrice", () => {
  it("reads JSON-LD with list and sale price", () => {
    const html = `<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Yoga Mat","image":["https://cdn.example/m.jpg"],"offers":{"@type":"Offer","priceCurrency":"ILS","price":"79.90","priceSpecification":[{"@type":"UnitPriceSpecification","priceType":"https://schema.org/ListPrice","price":"129.90"}]}}</script>`;
    const r = extractPrice(html, U);
    expect(r).toMatchObject({ found: true, name: "Yoga Mat", currency: "ILS", salePrice: 79.9, regularPrice: 129.9, onSale: true, image: "https://cdn.example/m.jpg" });
  });
  it("reads Shopify-style meta tags and handles @graph", () => {
    const html = `<meta property="og:title" content="Mat &amp; Strap"><meta property="og:image" content="//cdn.example/x.png"><meta property="product:price:amount" content="1,299.00"><meta property="product:price:currency" content="USD"><meta property="product:sale_price:amount" content="999.00">`;
    const r = extractPrice(html, U);
    expect(r).toMatchObject({ found: true, name: "Mat & Strap", salePrice: 999, regularPrice: 1299, onSale: true, image: "https://cdn.example/x.png" });
    const g = extractPrice(`<script type="application/ld+json">{"@graph":[{"@type":"WebSite"},{"@type":"Product","name":"G","offers":{"price":5,"priceCurrency":"EUR"}}]}</script>`, U);
    expect(g).toMatchObject({ found: true, regularPrice: 5, salePrice: null, onSale: false });
  });
  it("uses a strikethrough as the regular price hint", () => {
    const r = extractPrice(`<span itemprop="price" content="50">50</span><del>$80.00</del>`, U);
    expect(r).toMatchObject({ found: true, salePrice: 50, regularPrice: 80, onSale: true });
  });
  it("refuses non-https images and says plainly when nothing is published", () => {
    expect(extractPrice(`<script type="application/ld+json">{"@type":"Product","name":"A","image":"http://x/a.jpg","offers":{"price":"3"}}</script>`, U).image).toBeNull();
    expect(extractPrice(`<script type="application/ld+json">{"@type":"Product","image":"javascript:alert(1)","offers":{"price":"3"}}</script>`, U).image).toBeNull();
    const r = extractPrice("<html><body>$$ loaded by JS</body></html>", U);
    expect(r.found).toBe(false); expect(r.note).toMatch(/JavaScript/);
  });
  it("survives broken JSON-LD", () => { expect(extractPrice(`<script type="application/ld+json">{oops</script>`, U).found).toBe(false); });
});

describe("safeFetch in public mode", () => {
  const deps = (ips: string[]): Deps => ({ resolve: async () => ips, get: async () => ({ status: 200, headers: {}, body: Buffer.from("ok") }) });
  const code = async (url: string, d: Deps, o = {}) => safeFetch(url, { allowHosts: [], allowAnyPublic: true, ...o }, d).then(() => "ok", (e: SafeFetchError) => e.code);
  it("allows any public https host", async () => { expect(await code("https://any-shop.example/x", deps(["93.184.216.34"]))).toBe("ok"); });
  it("still blocks private targets, odd ports, plain http, credentials, internal names", async () => {
    expect(await code("https://evil.example/", deps(["10.0.0.5"]))).toBe("blocked_ip");
    expect(await code("https://evil.example/", deps(["93.184.216.34", "127.0.0.1"]))).toBe("blocked_ip");
    expect(await code("https://169.254.169.254/latest", deps(["93.184.216.34"]))).toBe("blocked_ip");
    expect(await code("https://shop.example:8443/", deps(["93.184.216.34"]))).toBe("bad_port");
    expect(await code("https://shop.example:22/", deps(["93.184.216.34"]), { allowPorts: [22] })).toBe("bad_port");
    expect(await code("http://shop.example/", deps(["93.184.216.34"]))).toBe("bad_scheme");
    expect(await code("https://u:p@shop.example/", deps(["93.184.216.34"]))).toBe("bad_url");
    expect(await code("https://localhost/", deps(["93.184.216.34"]))).toBe("host_not_allowed");
    expect(await code("https://printer.local/", deps(["93.184.216.34"]))).toBe("host_not_allowed");
  });
  it("without allowAnyPublic an empty allowlist is still refused", async () => {
    expect(await safeFetch("https://a.example/", { allowHosts: [] }, deps(["93.184.216.34"])).then(() => "ok", (e: SafeFetchError) => e.code)).toBe("no_allowlist");
  });
});
