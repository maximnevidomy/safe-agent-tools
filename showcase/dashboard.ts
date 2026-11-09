// Builds the public, read-only dashboard: one self-contained HTML page, no scripts, no external requests.
// "Before" = a naive baseline we wrote for the same idea (NOT the original project's code, which we did not run).
import { execSync } from "node:child_process";
import { BENIGN_SKILLS, benignFalseAlarms, runAttacks, type AttackResult, type ToolId } from "./attacks";
import { examples } from "./examples";
import { COMPARE } from "./compare";
import { TOOLS } from "./originals";
import { TRY_BY_ID, type Field } from "./try";

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
const cell = (r: AttackResult) => r.succeeded === null ? `<span class="na">n/a</span>` : r.succeeded ? `<span class="bad">got through</span>` : `<span class="ok">stopped</span>`;
const tone = (n: number) => (n >= 90 ? "good" : n >= 50 ? "mid" : "low");
const bar = (label: string, n: number) => `<div class="bar"><span class="bl">${label}</span><div class="track"><div class="fill ${tone(n)}" style="width:${n}%"></div></div><b>${n}%</b></div>`;

export interface DashboardMeta { generatedAt: string; commit: string }
export function gitMeta(): DashboardMeta {
  let commit = "unknown"; try { commit = execSync("git rev-parse --short HEAD", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim(); } catch { /* not a git checkout */ }
  return { generatedAt: new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC", commit };
}

const field = (f: Field) => {
  const id = `f-${f.name}`;
  const ctl = f.kind === "textarea" ? `<textarea id="${id}" name="${f.name}" rows="6" maxlength="${f.max}">${esc(f.value)}</textarea>`
    : f.kind === "select" ? `<select id="${id}" name="${f.name}">${(f.options ?? []).map((o) => `<option${o === f.value ? " selected" : ""}>${esc(o)}</option>`).join("")}</select>`
    : `<input id="${id}" name="${f.name}" type="text" maxlength="${f.max}" value="${esc(f.value)}" autocomplete="off" spellcheck="false">`;
  const ex = (f.examples ?? []).map((e) => `<button type="button" class="ghost" data-fill="${f.name}" data-value="${esc(e.value)}">${esc(e.label)}</button>`).join("");
  return `<div class="fld"><label for="${id}">${esc(f.label)}</label>${ctl}${ex ? `<div class="exs">${ex}</div>` : ""}</div>`;
};
const tryForm = (id: ToolId) => {
  const d = TRY_BY_ID.get(id); if (!d) return "";
  return `<h3>Try it yourself (live)</h3><form class="try" data-tool="${id}" autocomplete="off"><p class="muted">${esc(d.intro)}</p>${d.fields.map(field).join("")}<button type="submit">${esc(d.button)}</button><div class="out" aria-live="polite"></div></form>`;
};

const CMP_LABEL: Record<string, [string, string]> = { better: ["Ours is stronger", "ok"], same: ["About equal", "ok"], partial: ["Partly there", "mid"], missing: ["Not built", "bad"], "by-design": ["Left out on purpose", "na"] };
const compareTable = (id: ToolId, orig: string, name: string) =>
  `<h3>${esc(orig)} vs ${esc(name)}</h3><div class="cmpwrap"><table class="cmp"><thead><tr><th>Capability</th><th>Where we stand</th><th>${esc(orig)}</th><th>${esc(name)}</th></tr></thead><tbody>${(COMPARE[id] ?? []).map((r) => { const [l, c] = CMP_LABEL[r.status]!; return `<tr><td>${esc(r.what)}</td><td class="${c}">${l}</td><td>${esc(r.original)}</td><td>${esc(r.ours)}</td></tr>`; }).join("")}</tbody></table></div>`;

export async function buildDashboard(meta: DashboardMeta = gitMeta(), fragment = false, live = false): Promise<string> {
  const [scores, ex] = await Promise.all([runAttacks(), examples()]);
  const ids = TOOLS.map((t) => t.id) as ToolId[];
  const avg = (k: "naiveScore" | "safeScore") => Math.round(ids.reduce((a, i) => a + scores[i][k], 0) / ids.length);
  const totalAttacks = ids.reduce((a, i) => a + scores[i].applicable, 0);
  const falseAlarms = benignFalseAlarms();

  const FEATURED: ToolId[] = ["safe-fetch", "launch-check", "safe-reach"];
  const secs = TOOLS.map((t, n) => {
    const s = scores[t.id], e = ex[t.id];
    const rows = s.items.map((i) => `<tr><td>${esc(i.title)}</td><td>${cell(i.naive)}</td><td>${cell(i.safe)}</td></tr>`).join("");
    const also = t.original.also ? ` · also <a href="${esc(t.original.also.url)}" rel="noopener noreferrer">${esc(t.original.also.name)}</a>` : "";
    const featured = FEATURED.includes(t.id);
    const wrap = (inner: string) => featured ? `<section id="${t.id}">${inner}</section>` : `<details class="tool" id="${t.id}"><summary><b>${esc(t.name)}</b> <span class="muted">${esc(t.idea)}</span> <b class="${tone(s.safeScore)}">${s.safeScore}%</b></summary><section>${inner}</section></details>`;
    return { featured, html: wrap(`
<h2><span class="n">${n + 1}</span>${esc(t.name)} <small>${esc(t.idea)}</small></h2>
<div class="scores">${bar("Before: simple version (our baseline, not the original)", s.naiveScore)}${bar("After (" + esc(t.name) + ")", s.safeScore)}<p class="muted">${s.applicable} attack attempts. Score = share of attacks stopped.</p></div>
<div class="grid">
<div><h3>The original idea</h3><p><a href="${esc(t.original.url)}" rel="noopener noreferrer">${esc(t.original.name)}</a>${also}</p><p class="muted">From the tool library review: trust ${t.original.libraryTrust}/100 · ${esc(t.original.libraryStatus)}.<br>${esc(t.original.libraryNote)}</p></div>
<div><h3>The problem</h3><p>${esc(t.problem)}</p></div>
</div>
${compareTable(t.id, t.original.name, t.name)}
<h3>What we changed</h3><ul>${t.changes.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>
<h3>Attacks, before vs after</h3><table><thead><tr><th>Attack</th><th>Simple version</th><th>${esc(t.name)}</th></tr></thead><tbody>${rows}</tbody></table>
${live ? tryForm(t.id) : ""}
<h3>${live ? "Recorded example" : "It works: live example"}</h3><div class="ex"><div><b>Input</b><pre>${esc(e.input)}</pre></div><div><b>Result (recorded when this page was built)</b><pre>${esc(e.output)}</pre></div></div>
${e.simulated ? `<p class="muted">Simulated in this example: ${esc(e.simulated)}.</p>` : `<p class="muted">Nothing simulated: the real module ran on this machine.</p>`}
<h3>Still not covered</h3><ul class="muted">${t.notCovered.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>
`) };
  });
  const sections = secs.filter((x) => x.featured).map((x) => x.html).join("\n")
    + `\n<h2 class="more">${secs.filter((x) => !x.featured).length} more tools <small>Same format: original, problem, scores, live form. Open any one.</small></h2>\n` + secs.filter((x) => !x.featured).map((x) => x.html).join("\n");

  const nav = TOOLS.filter((t) => FEATURED.includes(t.id)).map((t) => `<a href="#${t.id}">${esc(t.name)} <b class="${tone(scores[t.id].safeScore)}">${scores[t.id].safeScore}</b></a>`).join("");
  const head = fragment ? "" : `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`;
  const open = fragment ? "" : `</head><body>`, close = fragment ? "" : `</body></html>`;
  return `${head}<title>Safe Agent Tools</title><meta name="claude:viewport-fit-sides" content="cover">
<style>
:root{--bg:#0f1115;--fg:#e8eaee;--mut:#9aa3b2;--card:#171a21;--line:#262b36;--good:#2fbf71;--mid:#e0a526;--low:#e5534b;--acc:#6ea8fe;color-scheme:dark}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]){--bg:#f6f7f9;--fg:#15181e;--mut:#5a6372;--card:#fff;--line:#dde1e8;--acc:#1d5fd0;--good:#16864a;--mid:#946a00;--low:#c0332b;color-scheme:light}}
:root[data-theme="light"]{--bg:#f6f7f9;--fg:#15181e;--mut:#5a6372;--card:#fff;--line:#dde1e8;--acc:#1d5fd0;--good:#16864a;--mid:#946a00;--low:#c0332b;color-scheme:light}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;padding-block:24px 64px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
main{max-width:980px;margin:0 auto}a{color:var(--acc)}h1{font-size:1.9rem;margin:.2em 0}h2{font-size:1.35rem;margin:0 0 .6em}h2 small{display:block;font-weight:400;color:var(--mut);font-size:.95rem}h3{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:1.3em 0 .4em}
.n{display:inline-grid;place-items:center;width:1.7em;height:1.7em;border-radius:50%;background:var(--line);margin-right:.5em;font-size:.85em}
.hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:18px 0}.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}.stat b{font-size:2rem;display:block}
.good{color:var(--good)}.mid{color:var(--mid)}.low{color:var(--low)}.muted{color:var(--mut);font-size:.9rem}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}nav a{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 12px;text-decoration:none;color:var(--fg);font-size:.9rem}
section{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin:18px 0}
.bar{display:grid;grid-template-columns:260px 1fr 56px;align-items:center;gap:10px;margin:6px 0}.track{height:14px;background:var(--line);border-radius:7px;overflow:hidden}.fill{height:100%}.fill.good{background:var(--good)}.fill.mid{background:var(--mid)}.fill.low{background:var(--low)}.bar b{text-align:right}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}
table{width:100%;border-collapse:collapse;font-size:.92rem}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}th{color:var(--mut);font-weight:600}
.cmpwrap{overflow-x:auto}.cmp{min-width:560px}.cmp td:first-child{font-weight:600}.cmp td{vertical-align:top}.ok{color:var(--good);font-weight:600}.bad{color:var(--low);font-weight:600}.na{color:var(--mut)}
.ex{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:.85rem;margin:.3em 0}
form.try{display:grid;gap:12px}.fld{display:grid;gap:4px}label{font-size:.85rem;color:var(--mut)}input,textarea,select{width:100%;font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px}textarea{font-family:ui-monospace,Consolas,monospace;font-size:.85rem}
button[type=submit]{justify-self:start;font:inherit;font-weight:600;background:var(--acc);color:var(--bg);border:0;border-radius:8px;padding:9px 18px;cursor:pointer}button:disabled{opacity:.6;cursor:wait}button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,a:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.exs{display:flex;flex-wrap:wrap;gap:6px}.ghost{font:inherit;font-size:.8rem;background:transparent;color:var(--acc);border:1px dashed var(--line);border-radius:999px;padding:3px 10px;cursor:pointer}
.res{border:1px solid var(--line);border-radius:10px;padding:12px;margin-top:4px}.res.blocked{border-color:var(--good)}.res.allowed{border-color:var(--acc)}.res dl{display:grid;grid-template-columns:minmax(90px,max-content) 1fr;gap:4px 12px;margin:.6em 0 0}.res dt{color:var(--mut);font-size:.85rem}.res dd{margin:0;white-space:pre-wrap;word-break:break-word}.pic{display:block;max-width:180px;max-height:180px;border-radius:8px;margin-top:8px}
details.tool{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:10px 0}details.tool>summary{cursor:pointer;padding:14px 18px;list-style:none}details.tool>summary::-webkit-details-marker{display:none}details.tool>summary::before{content:"+ ";color:var(--acc);font-weight:700}details.tool[open]>summary::before{content:"- "}details.tool>section{border:0;margin:0;padding-top:0}h2.more{margin-top:34px}.real{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin:16px 0}.real div{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}.note{border-left:4px solid var(--mid);background:var(--card);padding:12px 16px;border-radius:0 10px 10px 0;margin:16px 0}li{margin:.2em 0}
@media (max-width:560px){.bar{grid-template-columns:1fr 1fr 48px}.bar .bl{grid-column:1/-1}}
</style>${open}<main>
<h1>safe-agent-tools</h1>
<p><b>I took risky open-source AI-agent tools, rebuilt them with security first, and measured the result.</b> Three are shown in full below; seven more are one click away. Each one shows the original, its problem, a security score before and after, and a live example you can try.</p>
<div class="real"><div><b>Christina Fitness</b><br><span class="muted">Women's fitness and nutrition platform I build and run: React, Vite, Supabase, Paddle payments, edge functions.</span></div><div><b>Bath Plus website and competitor price monitor</b><br><span class="muted">I maintain the store's website (products, images, prices, orders) and am building a system that tracks competitor prices.</span></div></div>
<div class="hero"><div class="stat"><b class="low">${avg("naiveScore")}%</b>average score, naive baseline</div><div class="stat"><b class="good">${avg("safeScore")}%</b>average score, our tools</div><div class="stat"><b>${totalAttacks}</b>attack attempts run</div><div class="stat"><b>${falseAlarms}</b>false alarms on ${BENIGN_SKILLS.length} harmless skills</div></div>
<div class="note"><b>How to read the scores.</b> Every attack is run for real against two versions of the same idea: a deliberately simple "naive" version that we wrote, and our hardened tool. The score is the percentage of attacks stopped. The naive version is <b>not</b> the original project's code: we did not run or audit the originals. What we say about the originals comes from the tool library review and public repo metadata. 100% means "stopped every attack in this suite", not "unbreakable"; each section lists what is still not covered.</div>
${live ? `<div class="note"><b>Try everything yourself.</b> Each tool has a live form. Your input is not stored, nothing runs on your computer, and results are shown as plain text. The server holds no secrets and limits how often each visitor can try.</div>` : ""}
<nav>${nav}</nav>
${sections}
<p class="muted">Generated ${esc(meta.generatedAt)} · commit ${esc(meta.commit)} · ${live ? "no tracking, no cookies, nothing you type is stored." : "static page, no scripts, no tracking."}</p>
</main>${live ? `<script src="/app.js"></script>` : ""}${close}`;
}
