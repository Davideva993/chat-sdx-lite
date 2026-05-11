import "dotenv/config";
import { createServer } from "http";
import { initDb } from "./models/db.js";

const port = Number(process.env.PORT || 3001);


async function startServer() {
  try {
    await initDb();
    //console.log("Database synced");
    const { default: app } = await import("./app.js");
    const server = createServer(app);
    const { default: webSocketController } = await import("./controllers/ws.js");
    webSocketController.initWebSocket(server);
    const HOST= process.env.HOST || "127.0.0.1"
    server.listen(port, HOST ,() => console.log(`Server listening on port ${port}`));
  } catch (e) {
    console.error("Startup error:", e);
    process.exit(1);
  }
}

startServer();