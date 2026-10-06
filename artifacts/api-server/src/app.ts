import express, { type Express, type Request, type Response } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { pinoHttp } from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();

// Cross-origin setup for the split deployment:
//   - Vercel hosts the React dashboard (https://argus-*.vercel.app)
//   - Render hosts this API (https://argus-api-*.onrender.com)
// ARGUS_ALLOWED_ORIGINS is a comma-separated allowlist. When unset (local
// dev, single-origin deployments, desktop app) any origin is accepted.
const allowedOrigins = (process.env.ARGUS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req: Request) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res: Response) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
app.use(
  cors(
    allowedOrigins.length > 0
      ? {
          origin(origin, callback) {
            if (!origin || allowedOrigins.includes(origin)) callback(null, true);
            else callback(new Error(`Origin not allowed: ${origin}`));
          },
          credentials: true,
        }
      : { origin: true, credentials: true },
  ),
);
app.use(cookieParser());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/api", router);

export default app;
