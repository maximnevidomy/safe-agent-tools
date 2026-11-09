import fs from "node:fs";
import { buildDashboard, gitMeta } from "./dashboard";
fs.mkdirSync("site", { recursive: true });
const meta = gitMeta();
Promise.all([buildDashboard(meta), buildDashboard(meta, true)]).then(([h, frag]) => {
  fs.writeFileSync("site/index.html", h); fs.writeFileSync("site/artifact.html", frag);
  console.log(`site/index.html (${h.length} bytes) and site/artifact.html (${frag.length} bytes) written`);
});
