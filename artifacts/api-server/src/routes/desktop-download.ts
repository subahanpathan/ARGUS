import { Router, type IRouter, type Request, type Response } from "express";
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { logger } from "../lib/logger";

const router: IRouter = Router();

/**
 * Resolves the actual ARGUS Windows installer output path.
 *
 * It looks for the output from the Inno Setup build or PyInstaller bundle
 * in the workspace root.
 */
function findInstaller(): string | null {
  if (process.env.ARGUS_INSTALLER_PATH !== undefined) {
    const custom = process.env.ARGUS_INSTALLER_PATH;
    if (!custom) return null;
    try {
      if (existsSync(custom) && statSync(custom).isFile() && statSync(custom).size > 0) {
        return custom;
      }
    } catch {}
    return null;
  }

  // Try to find the workspace root regardless of whether we run from
  // artifacts/api-server or from the built dist/ bundle.
  const cwd = process.cwd();
  const rootDir = cwd.includes("artifacts")
    ? path.resolve(cwd, "..", "..")
    : cwd;

  const CANDIDATES = [
    path.resolve(rootDir, "dist", "installer", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "artifacts", "argus", "dist", "public", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "artifacts", "argus", "public", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "scripts", "dist", "ARGUS.exe"),
    path.resolve(rootDir, "dist", "app", "ARGUS.exe"),
    path.resolve(rootDir, "artifacts", "api-server", "downloads", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "artifacts", "api-server", "dist", "downloads", "ARGUS-Setup.exe"),
  ];

  for (const p of CANDIDATES) {
    try {
      if (existsSync(p)) {
        const stat = statSync(p);
        if (stat.isFile() && stat.size > 0) {
          return p;
        }
      }
    } catch {
      // ignore
    }
  }
  return null;
}

router.get(["/desktop/download", "/downloads/argus-windows"], (_req: Request, res: Response) => {
  const installer = findInstaller();
  if (installer) {
    logger.info({ installer }, "Serving desktop installer from bundle");
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", 'attachment; filename="ARGUS-Setup.exe"');
    res.sendFile(installer);
    return;
  }

  // Return a clear 404 error instead of redirecting when not found
  res.status(404).json({ error: "ARGUS Windows installer is not available" });
});

router.head(["/desktop/download", "/downloads/argus-windows"], (_req: Request, res: Response) => {
  if (findInstaller()) {
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", 'attachment; filename="ARGUS-Setup.exe"');
    res.end();
    return;
  }

  res.status(404).end();
});

export default router;
