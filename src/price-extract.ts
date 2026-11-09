// price-extract: pulls product name, image, regular price and sale price out of an HTML page using ONLY structured
// data the shop publishes for search engines (JSON-LD, OpenGraph/product meta, microdata) plus a strikethrough hint.
// Pure function: no network, no script execution. Pages that load prices with JavaScript are reported as "not found".
export interface PriceResult {
  found: boolean;
  name: string | null;
  image: string | null; // https URL only
  currency: string | null;
  regularPrice: number | null;
  salePrice: number | null;
  onSale: boolean;
  source: string; // which kind of data the answer came from
  note?: string;
}

const entities = (s: string) => s.replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&#x2F;/g, "/");
const num = (v: unknown): number | null => {
  if (typeof v === "number") return Number.isFinite(v) && v >= 0 ? v : null;
  if (typeof v !== "string") return null;
  let t = v.replace(/[^\d.,]/g, "");
  if (!t) return null;
  if (t.includes(",") && t.includes(".")) t = t.lastIndexOf(",") > t.lastIndexOf(".") ? t.replace(/\./g, "").replace(",", ".") : t.replace(/,/g, "");
  else if (t.includes(",")) t = /,\d{1,2}$/.test(t) ? t.replace(",", ".") : t.replace(/,/g, "");
  const n = Number(t);
  return Number.isFinite(n) && n >= 0 ? n : null;
};
const clean = (v: unknown, max = 200) => (typeof v === "string" ? entities(v).replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim().slice(0, max) || null : null);
const httpsUrl = (v: unknown, base: string): string | null => {
  const first = Array.isArray(v) ? v[0] : v;
  const raw = typeof first === "object" && first && "url" in first ? (first as { url: unknown }).url : first;
  if (typeof raw !== "string") return null;
  try { const u = new URL(entities(raw), base); return u.protocol === "https:" ? u.toString() : null; } catch { return null; }
};
const meta = (html: string, key: string): string | null => {
  const re = new RegExp(`<meta\\b[^>]*\\b(?:property|name|itemprop)=["']${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'][^>]*>`, "i");
  const tag = re.exec(html)?.[0];
  const c = tag && /\bcontent=["']([^"']*)["']/i.exec(tag)?.[1];
  return c ? entities(c) : null;
};

function* jsonLdNodes(html: string): Generator<Record<string, any>> {
  for (const m of html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    let data: unknown; try { data = JSON.parse(m[1]!.trim()); } catch { continue; }
    const stack: unknown[] = [data]; let guard = 0;
    while (stack.length && guard++ < 500) {
      const n = stack.pop();
      if (Array.isArray(n)) stack.push(...n);
      else if (n && typeof n === "object") { yield n as Record<string, any>; const g = (n as any)["@graph"]; if (Array.isArray(g)) stack.push(...g); }
    }
  }
}
const isType = (n: Record<string, any>, t: string) => [].concat(n["@type"] ?? []).some((x: string) => String(x).toLowerCase().endsWith(t.toLowerCase()));

export function extractPrice(html: string, pageUrl: string): PriceResult {
  const out: PriceResult = { found: false, name: null, image: null, currency: null, regularPrice: null, salePrice: null, onSale: false, source: "none" };
  const head = html.slice(0, 1_500_000);

  // 1) schema.org Product in JSON-LD
  for (const n of jsonLdNodes(head)) {
    if (!isType(n, "Product")) continue;
    out.name = clean(n.name); out.image = httpsUrl(n.image, pageUrl);
    const offers = ([] as any[]).concat(n.offers ?? []).flatMap((o) => (o && typeof o === "object" ? ([] as any[]).concat(o.offers ?? o) : []));
    const o = offers[0];
    if (o) {
      out.currency = clean(o.priceCurrency, 8);
      const specs = ([] as any[]).concat(o.priceSpecification ?? []);
      const list = specs.find((x) => /ListPrice|Strikethrough|MSRP/i.test(String(x?.priceType ?? "")));
      const sale = specs.find((x) => /SalePrice/i.test(String(x?.priceType ?? "")));
      const price = num(o.price ?? o.lowPrice ?? sale?.price ?? specs[0]?.price);
      const listP = num(list?.price);
      out.salePrice = price;
      out.regularPrice = listP;
      if (listP !== null && price !== null && listP > price) out.onSale = true;
      if (price !== null) { out.found = true; out.source = "JSON-LD (schema.org Product)"; }
    }
    if (out.found) break;
  }

  // 2) OpenGraph / product meta tags (Shopify, WooCommerce and others publish these)
  if (!out.found || out.regularPrice === null) {
    const cur = meta(head, "product:price:currency") ?? meta(head, "og:price:currency");
    const price = num(meta(head, "product:price:amount") ?? meta(head, "og:price:amount"));
    const sale = num(meta(head, "product:sale_price:amount"));
    const orig = num(meta(head, "product:original_price:amount") ?? meta(head, "product:compare_at_price:amount"));
    if (price !== null || sale !== null) {
      if (!out.found) { out.name = out.name ?? clean(meta(head, "og:title")); out.image = out.image ?? httpsUrl(meta(head, "og:image:secure_url") ?? meta(head, "og:image"), pageUrl); out.currency = cur ?? out.currency; out.source = "OpenGraph / product meta tags"; }
      const effective = sale ?? price;
      const regular = orig ?? (sale !== null && price !== null && price > sale ? price : null);
      out.salePrice = effective; out.regularPrice = regular ?? out.regularPrice;
      out.onSale = out.regularPrice !== null && effective !== null && out.regularPrice > effective;
      out.found = true;
    }
  }

  // 3) microdata itemprop="price"
  if (!out.found) {
    const p = /itemprop=["']price["'][^>]*?(?:content=["']([^"']+)["']|>([^<]+)<)/i.exec(head);
    const v = num(p?.[1] ?? p?.[2]);
    if (v !== null) { out.salePrice = v; out.found = true; out.source = "microdata (itemprop=price)"; out.name = clean(/itemprop=["']name["'][^>]*>([^<]+)</i.exec(head)?.[1]) ?? clean(meta(head, "og:title")); out.image = httpsUrl(meta(head, "og:image"), pageUrl); out.currency = clean(meta(head, "priceCurrency"), 8); }
  }

  // 4) strikethrough hint for the regular price when the sale price is known
  if (out.found && out.regularPrice === null) {
    const del = [...head.matchAll(/<(?:del|s|strike)\b[^>]*>([\s\S]{0,80}?)<\/(?:del|s|strike)>/gi)].map((m) => num(m[1]!.replace(/<[^>]*>/g, ""))).find((x) => x !== null && out.salePrice !== null && x > out.salePrice);
    if (del != null) { out.regularPrice = del; out.onSale = true; out.source += " + strikethrough price in the page"; }
  }
  if (out.found && out.regularPrice === null) { out.regularPrice = out.salePrice; out.salePrice = null; out.note = "No sale price published: this is the regular price."; }
  if (!out.found) out.note = "No price found in the page's published data. Many shops load prices with JavaScript after the page opens; this tool does not run page scripts.";
  return out;
}
