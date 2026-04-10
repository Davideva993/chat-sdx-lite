import express from "express";
import helmet from "helmet";
import cors from "cors";
import routes from "./routes/routes.js";

const app = express();

app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "1.5mb" }));
app.use(express.urlencoded({ limit: "1.5mb", extended: true }));

app.use(helmet());

app.use("/api", routes);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

export default app;
