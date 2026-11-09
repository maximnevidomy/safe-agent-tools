import { buildDashboard } from "./dashboard";
import { createPublicApp } from "./public-app";

const port = Number(process.env.PORT ?? 10000); // Render provides PORT
const app = createPublicApp({ html: () => buildDashboard(undefined, false, true) });
app.server.listen(port, "0.0.0.0", () => {
  console.log(`Safe Agent Tools (public) listening on ${port}`);
  app.ready().then(() => console.log("page ready"), (e) => console.error("page build failed", e));
});
