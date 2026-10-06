import { Router, type IRouter } from "express";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { logger } from "../lib/logger";

const router: IRouter = Router();

/**
 * Serves the ARGUS desktop installer when it is bundled next to the server.
 *
 * Layouts supported (relative to the server bundle directory):
 *   downloads/ARGUS-Setup.exe   <- preferred: drop the installer in ./downloads
 *   ../downloads/ARGUS-Setup.exe
 *
 * If no installer is bundled the endpoint reports 404 with a JSON error so the
 * UI can fall back gracefully.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const CANDIDATES = [
  path.resolve(here, "downloads", "ARGUS-Setup.exe"),
  path.resolve(here, "..", "downloads", "ARGUS-Setup.exe"),
  path.resolve(here, "ARGUS-Setup.exe"),
];

function findInstaller(): string | null {
  for (const p of CANDIDATES) {
    try {
      if (existsSync(p)) return p;
    } catch {
      // ignore
    }
  }
  return null;
}

/**
 * Fallback for serverless hosts (Vercel et al.), where the function bundle
 * contains only code - a 73MB exe is served as a STATIC ASSET from the
 * frontend's public/ directory instead (globally cached, zero function
 * bandwidth). Drop the installer in the web app's public folder as
 * ARGUS-Setup.exe and this route redirects to it.
 */
const STATIC_FALLBACK = "/ARGUS-Setup.exe";

router.get("/desktop/download", (_req, res) => {
  const installer = findInstaller();
  if (installer) {
    logger.info({ installer }, "Serving desktop installer from bundle");
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", 'attachment; filename="ARGUS-Setup.exe"');
    res.sendFile(installer);
    return;
  }
  // Serverless / static-hosting fallback: redirect to the public asset.
  res.redirect(302, STATIC_FALLBACK);
});

router.head("/desktop/download", (_req, res) => {
  if (findInstaller()) {
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", 'attachment; filename="ARGUS-Setup.exe"');
    res.end();
    return;
  }
  // Probe the static asset path so the UI can tell "available" vs "missing".
  // Follows the redirect to /ARGUS-Setup.exe; static host answers 200/404.
  res.redirect(302, STATIC_FALLBACK);
});

export default router;
