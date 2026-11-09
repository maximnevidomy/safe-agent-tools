// Browser script for the live site. Served from /app.js (CSP: script-src 'self'). Results are written with
// textContent only; the only attribute set from server data is an image data: URI that is checked first.
export const CLIENT_JS = `(() => {
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  document.querySelectorAll("form.try").forEach((form) => {
    const out = form.querySelector(".out"), btn = form.querySelector("button[type=submit]");
    form.querySelectorAll("[data-fill]").forEach((b) => b.addEventListener("click", () => { const f = form.elements[b.dataset.fill]; if (f) { f.value = b.dataset.value; f.focus(); } }));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const body = {}; for (const f of form.elements) if (f.name) body[f.name] = f.value;
      btn.disabled = true; out.replaceChildren(el("p", "muted", "Running..."));
      try {
        const r = await fetch("/api/try/" + form.dataset.tool, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) { out.replaceChildren(el("p", "res info", j.error || "Something went wrong. Try again in a moment.")); return; }
        const box = el("div", "res " + j.verdict);
        box.append(el("b", "", (j.verdict === "blocked" ? "Stopped by the tool: " : "") + j.headline));
        if (typeof j.image === "string" && /^data:image\\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+\\/=]+$/.test(j.image)) { const im = el("img", "pic"); im.alt = "Product image fetched safely by the server"; im.src = j.image; box.append(im); }
        const dl = el("dl"); for (const [k, v] of j.rows || []) { dl.append(el("dt", "", String(k)), el("dd", "", String(v))); } box.append(dl);
        out.replaceChildren(box);
      } catch { out.replaceChildren(el("p", "res info", "The server did not answer. It may be waking up: wait a minute and try again.")); }
      finally { btn.disabled = false; }
    });
  });
})();`;
