import app from "./app";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import express from "express";
import { logger } from "./lib/logger";
import { isDesktopEnvironment } from "./lib/activation";

// Serve the built React dashboard from ./public next to the bundle
// (desktop/production mode). On Vercel the vercel entry point is used instead.
const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(here, "public");
if (fs.existsSync(publicDir)) {
  // Never expose Windows installer / PE binaries via static hosting — downloads
  // must go through the authenticated /api/desktop/download route.
  app.use((req, res, next) => {
    if (/\.(exe|msi|msix)$/i.test(req.path)) {
      res.status(404).json({
        error: "Installer downloads require activation",
        code: "ACTIVATION_REQUIRED",
      });
      return;
    }
    next();
  });

  app.use(express.static(publicDir, {
    setHeaders(res, filePath) {
      if (/\.(exe|msi|msix)$/i.test(filePath)) {
        res.setHeader("X-Content-Type-Options", "nosniff");
      }
    },
  }));

  app.use((req, res, next) => {
    if (req.path.startsWith("/api/") || req.method !== "GET") return next();

    const indexPath = path.join(publicDir, "index.html");
    if (!fs.existsSync(indexPath)) return next();

    // Inject desktop marker so the SPA uses in-app activation (not website download).
    if (isDesktopEnvironment()) {
      try {
        let html = fs.readFileSync(indexPath, "utf8");
        if (!html.includes("__ARGUS_DESKTOP__")) {
          html = html.replace(
            /<head([^>]*)>/i,
            `<head$1><script>window.__ARGUS_DESKTOP__=true;</script>`,
          );
        }
        res.type("html").send(html);
        return;
      } catch {
        // fall through to sendFile
      }
    }

    res.sendFile(indexPath);
  });
  logger.info({ publicDir }, "Serving dashboard from public directory");
}

const port = Number(process.env["PORT"] || "5000");

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${process.env["PORT"]}"`);
}

// Desktop binds loopback only. Hosted (Render/Vercel sidecars) must listen on all interfaces.
const host =
  process.env["HOST"]?.trim() ||
  (isDesktopEnvironment() ? "127.0.0.1" : "0.0.0.0");

app.listen(port, host, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port, host }, "Server listening");
});
