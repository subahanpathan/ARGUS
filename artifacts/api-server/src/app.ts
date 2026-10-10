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

if (process.env.VERCEL) {
  app.use((req: Request, _res: Response, next) => {
    next();
  });
} else {
  try {
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
  } catch {}
}

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

import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

let publicDir = "";
try {
  const currentFilename = fileURLToPath(import.meta.url);
  publicDir = path.join(path.dirname(currentFilename), "public");
} catch {
  publicDir = path.join(process.cwd(), "public");
}

if (!fs.existsSync(publicDir)) {
  const cwdDistPublic = path.join(process.cwd(), "dist", "public");
  if (fs.existsSync(cwdDistPublic)) {
    publicDir = cwdDistPublic;
  }
}

if (publicDir && fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
}

// Explicit direct download handlers for sensor scripts
app.get(["/start-sensor.bat", "/api/start-sensor.bat"], (_req: Request, res: Response) => {
  const file = path.join(publicDir, "start-sensor.bat");
  if (file && fs.existsSync(file)) {
    res.setHeader("Content-Type", "application/x-msdos-program");
    res.setHeader("Content-Disposition", "attachment; filename=start-sensor.bat");
    res.sendFile(file);
  } else {
    res.status(404).send("start-sensor.bat not found");
  }
});

app.get(["/start-sensor.ps1", "/api/start-sensor.ps1"], (_req: Request, res: Response) => {
  const file = path.join(publicDir, "start-sensor.ps1");
  if (file && fs.existsSync(file)) {
    res.setHeader("Content-Type", "text/plain");
    res.setHeader("Content-Disposition", "attachment; filename=start-sensor.ps1");
    res.sendFile(file);
  } else {
    res.status(404).send("start-sensor.ps1 not found");
  }
});

app.get(["/argus_sensor.py", "/api/argus_sensor.py"], (_req: Request, res: Response) => {
  const file = path.join(publicDir, "argus_sensor.py");
  if (file && fs.existsSync(file)) {
    res.setHeader("Content-Type", "text/x-python");
    res.setHeader("Content-Disposition", "attachment; filename=argus_sensor.py");
    res.sendFile(file);
  } else {
    res.status(404).send("argus_sensor.py not found");
  }
});

app.use("/api", router);
app.use(router);

// Express global error handler to prevent unhandled 500 HTML crashes
app.use((err: any, _req: Request, res: Response, _next: any) => {
  const message = err?.message || "Internal server error";
  res.status(500).json({ success: false, error: "SERVER_ERROR", message });
});

export default app;

