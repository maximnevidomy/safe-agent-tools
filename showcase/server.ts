import os from "node:os";
import path from "node:path";
import { createApp } from "./app";
import { buildDashboard } from "./dashboard";

const port = Number(process.env.PORT ?? 4173);
// Folders the app may scan. Default: the parent of this repo, so sibling projects (for example christina.fitness) are reachable.
const roots = (process.env.DEMO_ROOTS ? process.env.DEMO_ROOTS.split(path.delimiter) : [path.resolve(process.cwd(), "..")]).filter(Boolean);
const app = createApp({
  roots,
  port,
  outboxDir: path.resolve(process.cwd(), "data"),
  igSecret: process.env.IG_APP_SECRET,
  igVerifyToken: process.env.IG_VERIFY_TOKEN,
  githubToken: process.env.GITHUB_TOKEN,
  gateSecret: process.env.GATE_SECRET,
  publicHost: process.env.PUBLIC_HOST, // tunnel hostname, e.g. abc.trycloudflare.com
  dashboardHtml: () => buildDashboard(),
});
app.server.listen(port, "127.0.0.1", () => {
  console.log(`Safe Agent Tools running at http://127.0.0.1:${port}`);
  console.log(`Folders it may scan: ${roots.join(", ")}`);
  console.log(`Instagram webhook: ${process.env.IG_APP_SECRET && process.env.IG_VERIFY_TOKEN ? "enabled at /webhook/instagram" : "disabled (set IG_APP_SECRET and IG_VERIFY_TOKEN)"}`);
  console.log(`Dashboard: http://127.0.0.1:${port}/dashboard`);
  console.log(process.env.PUBLIC_HOST ? `Public host ${process.env.PUBLIC_HOST} serves the read-only dashboard only` : "Public host: off (set PUBLIC_HOST to the tunnel hostname)");
  void os;
});
