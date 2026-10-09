/**
 * ARGUS Secure Windows Installer Download Endpoint.
 *
 * Implements:
 * 1. Authorization: activation cookie/header, one-time download token, or desktop vault.
 * 2. Attachment headers: Content-Disposition attachment with ARGUS-Setup.exe filename.
 * 3. Resumable downloads: HTTP Range (206) for interrupted transfers.
 * 4. Optional remote fallback via ARGUS_INSTALLER_URL when no local installer exists.
 */

import { Router, type IRouter, type Request, type Response } from "express";
import { existsSync, statSync, createReadStream } from "node:fs";
import path from "node:path";
import { logger } from "../lib/logger";
import {
  ACTIVATION_COOKIE,
  verifyActivationToken,
  verifyDownloadToken,
  consumeDownloadToken,
  verifyDesktopLicense,
} from "../lib/activation";

const router: IRouter = Router();

/**
 * Resolves the actual ARGUS Windows installer output path.
 */
export function findInstaller(): string | null {
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

  const cwd = process.cwd();
  const rootDir = cwd.includes("artifacts")
    ? path.resolve(cwd, "..", "..")
    : cwd;

  const CANDIDATES = [
    path.resolve(rootDir, "dist", "installer", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "artifacts", "api-server", "downloads", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "artifacts", "api-server", "dist", "downloads", "ARGUS-Setup.exe"),
    path.resolve(cwd, "downloads", "ARGUS-Setup.exe"),
    // Legacy locations (still authorized-only via this route; never via express.static)
    path.resolve(rootDir, "artifacts", "argus", "dist", "public", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "artifacts", "argus", "public", "ARGUS-Setup.exe"),
    path.resolve(rootDir, "dist", "app", "ARGUS.exe"),
    path.resolve(rootDir, "scripts", "dist", "ARGUS.exe"),
  ];

  for (const p of CANDIDATES) {
    try {
      if (existsSync(p)) {
        const stat = statSync(p);
        if (stat.isFile() && stat.size > 0) {
          return p;
        }
      }
    } catch {}
  }
  return null;
}

function remoteInstallerUrl(): string | null {
  const url = process.env.ARGUS_INSTALLER_URL?.trim();
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

type DownloadAuth =
  | { ok: true; via: "download-token"; token: string }
  | { ok: true; via: "session" | "desktop" | "anonymous" }
  | { ok: false };

/** Check if the caller is authorized to download the installer. */
export function authorizeDownload(req: Request): DownloadAuth {
  const isRange = Boolean(req.headers.range && String(req.headers.range).startsWith("bytes="));

  const tokenQuery = req.query.token;
  if (typeof tokenQuery === "string" && tokenQuery.length > 0) {
    if (verifyDownloadToken(tokenQuery, { forResume: isRange })) {
      return { ok: true, via: "download-token", token: tokenQuery };
    }
    return { ok: false };
  }

  const cookieToken = req.cookies?.[ACTIVATION_COOKIE];
  if (typeof cookieToken === "string" && verifyActivationToken(cookieToken)) {
    return { ok: true, via: "session" };
  }

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    if (verifyActivationToken(authHeader.slice(7).trim())) {
      return { ok: true, via: "session" };
    }
  }

  const customHeader = req.headers["x-argus-activation"];
  if (typeof customHeader === "string" && verifyActivationToken(customHeader)) {
    return { ok: true, via: "session" };
  }

  if (verifyDesktopLicense().valid) {
    return { ok: true, via: "desktop" };
  }

  if (process.env.ARGUS_ALLOW_ANONYMOUS_DOWNLOAD === "1") {
    return { ok: true, via: "anonymous" };
  }

  return { ok: false };
}

/** @deprecated use authorizeDownload */
export function isDownloadAuthorized(req: Request): boolean {
  return authorizeDownload(req).ok;
}

function serveLocalInstaller(req: Request, res: Response, installer: string): void {
  const stat = statSync(installer);
  const totalSize = stat.size;
  const filename = path.basename(installer).toLowerCase().endsWith(".exe")
    ? path.basename(installer)
    : "ARGUS-Setup.exe";

  logger.info({ installer, totalSize }, "Serving desktop installer download");

  const range = req.headers.range;
  if (range && range.startsWith("bytes=")) {
    const parts = range.replace(/bytes=/, "").split("-");
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;

    if (isNaN(start) || isNaN(end) || start >= totalSize || end >= totalSize || start > end) {
      res.status(416).setHeader("Content-Range", `bytes */${totalSize}`).end();
      return;
    }

    const chunkSize = end - start + 1;
    res.writeHead(206, {
      "Content-Range": `bytes ${start}-${end}/${totalSize}`,
      "Accept-Ranges": "bytes",
      "Content-Length": chunkSize,
      "Content-Type": "application/vnd.microsoft.portable-executable",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "private, no-store, no-transform",
    });

    createReadStream(installer, { start, end }).pipe(res);
    return;
  }

  res.writeHead(200, {
    "Content-Type": "application/vnd.microsoft.portable-executable",
    "Content-Disposition": `attachment; filename="${filename}"`,
    "Content-Length": totalSize,
    "Accept-Ranges": "bytes",
    "Cache-Control": "private, no-store, no-transform",
  });

  createReadStream(installer).pipe(res);
}

function handleDownload(req: Request, res: Response, method: "GET" | "HEAD"): void {
  const auth = authorizeDownload(req);
  if (!auth.ok) {
    if (method === "HEAD") {
      res.status(401).end();
      return;
    }
    res.status(401).json({
      error: "Activation required to download ARGUS Windows Installer",
      code: "ACTIVATION_REQUIRED",
    });
    return;
  }

  if (auth.via === "download-token" && method === "GET") {
    consumeDownloadToken(auth.token);
  }

  const installer = findInstaller();
  if (installer) {
    if (method === "HEAD") {
      const stat = statSync(installer);
      const filename = path.basename(installer);
      res.writeHead(200, {
        "Content-Type": "application/vnd.microsoft.portable-executable",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length": stat.size,
        "Accept-Ranges": "bytes",
        "Cache-Control": "private, no-store, no-transform",
      });
      res.end();
      return;
    }
    serveLocalInstaller(req, res, installer);
    return;
  }

  const remote = remoteInstallerUrl();
  if (remote) {
    logger.info({ remote }, "Redirecting desktop installer download to configured URL");
    res.setHeader("Cache-Control", "private, no-store, no-transform");
    res.redirect(302, remote);
    return;
  }

  if (method === "HEAD") {
    res.status(404).end();
    return;
  }
  res.status(404).json({
    error: "ARGUS Windows installer is not available",
    code: "INSTALLER_NOT_FOUND",
  });
}

router.get(["/desktop/download", "/downloads/argus-windows"], (req: Request, res: Response) => {
  handleDownload(req, res, "GET");
});

router.head(["/desktop/download", "/downloads/argus-windows"], (req: Request, res: Response) => {
  handleDownload(req, res, "HEAD");
});

export default router;
