import app from "./app";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import express, { type Express, type Request, type Response } from "express";
import { logger } from "./lib/logger";

// Serve the built React dashboard from ./public next to the bundle
// (desktop/production mode). On Vercel the vercel entry point is used instead.
const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(here, "public");
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  app.use((req, res, next) => {
    if (req.path.startsWith("/api/") || req.method !== "GET") return next();
    res.sendFile(path.join(publicDir, "index.html"));
  });
  logger.info({ publicDir }, "Serving dashboard from public directory");
}

const port = Number(process.env["PORT"] || "5000");

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${process.env["PORT"]}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
});
