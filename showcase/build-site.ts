import fs from "node:fs";
import { buildDashboard } from "./dashboard";
fs.mkdirSync("site", { recursive: true });
buildDashboard().then((h) => { fs.writeFileSync("site/index.html", h); console.log(`site/index.html written (${h.length} bytes)`); });
