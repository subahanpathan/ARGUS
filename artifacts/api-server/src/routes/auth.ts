/**
 * ARGUS activation and license management endpoints.
 *
 * Implements:
 * - Backend access-key validation with revocation, expiration, and constant-time comparison.
 * - Issuing signed activation tokens, download tokens, and persistent desktop license vaults.
 * - Secure status verification from both cookie/header and persistent hardware-bound vault.
 */

import { Router, type IRouter, type Request, type Response } from "express";

import {
  ACTIVATION_COOKIE,
  ACTIVATION_TTL_MS,
  activationCookieOptions,
  evaluateActivation,
  verifyActivationToken,
  saveDesktopLicense,
  verifyDesktopLicense,
  clearDesktopLicense,
  isDesktopEnvironment,
  getDeviceFingerprint,
} from "../lib/activation";
import { logger } from "../lib/logger";

const router: IRouter = Router();

type ActivateBody = { accessKey?: unknown };

function extractToken(req: Request): string | null {
  const cookieToken = req.cookies?.[ACTIVATION_COOKIE];
  if (cookieToken && typeof cookieToken === "string") return cookieToken;

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }

  const headerToken = req.headers["x-argus-activation"];
  if (headerToken && typeof headerToken === "string") {
    return headerToken.trim();
  }

  return null;
}

/**
 * POST /api/auth/activate
 *
 * 200 `{ success: true, status: "activated", downloadUrl: "...", isDesktop: true|false }`
 * 401 `{ success: false, code: "INVALID_ACCESS_KEY" | "LICENSE_EXPIRED" }`
 * 403 `{ success: false, code: "LICENSE_REVOKED" }`
 * 503 `{ success: false, code: "ACTIVATION_UNAVAILABLE" }`
 */
router.post("/auth/activate", (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as ActivateBody;
    const outcome = evaluateActivation(body.accessKey);

    if (!outcome.ok) {
      try {
        logger.warn(
          { scope: "activation", code: outcome.code, remote: req.socket?.remoteAddress },
          "rejected ARGUS activation attempt",
        );
      } catch {}
      const status =
        outcome.code === "ACTIVATION_UNAVAILABLE"
          ? 503
          : outcome.code === "LICENSE_REVOKED"
            ? 403
            : 401;
      res.status(status).json({ success: false, code: outcome.code });
      return;
    }

    // Set the HTTP cookie
    try {
      res.cookie(ACTIVATION_COOKIE, outcome.token, activationCookieOptions(ACTIVATION_TTL_MS, req));
    } catch {}

    const isDesktop = isDesktopEnvironment();

    // If running in local desktop environment, save persistent hardware-bound license
    if (isDesktop && typeof body.accessKey === "string") {
      try {
        saveDesktopLicense(body.accessKey, outcome.expiresAt);
      } catch {}
    }

    try {
      logger.info({ scope: "activation", isDesktop }, "ARGUS activation accepted");
    } catch {}

    const responsePayload: Record<string, any> = {
      success: true,
      status: "activated",
    };
    if (outcome.downloadToken) {
      responsePayload.downloadToken = outcome.downloadToken;
      responsePayload.downloadUrl = `/api/desktop/download?token=${outcome.downloadToken}`;
    }
    if (isDesktop) {
      responsePayload.isDesktop = true;
      try {
        responsePayload.deviceId = getDeviceFingerprint();
      } catch {}
    }

    res.json(responsePayload);
  } catch (err: any) {
    res.status(500).json({ success: false, code: "ACTIVATION_FAILED", message: err?.message || "Internal activation error" });
  }
});

/**
 * GET /api/auth/status
 *
 * Authoritative answer to "is this installation activated?".
 * Checks:
 * 1. Activation token in HttpOnly cookie or Authorization header
 * 2. Persistent machine-bound desktop license vault (when running as desktop app)
 */
router.get("/auth/status", (req: Request, res: Response) => {
  const isDesktop = isDesktopEnvironment();
  const token = extractToken(req);
  if (token && verifyActivationToken(token)) {
    const resp: Record<string, any> = { activated: true };
    if (isDesktop) resp.isDesktop = true;
    res.json(resp);
    return;
  }

  // Check persistent hardware-bound desktop license vault ONLY if running in desktop environment
  if (isDesktop) {
    const desktopCheck = verifyDesktopLicense();
    if (desktopCheck.valid) {
      res.json({ activated: true, isDesktop: true });
      return;
    }
  }

  const resp: Record<string, any> = { activated: false };
  if (isDesktop) resp.isDesktop = true;
  res.json(resp);
});

/**
 * POST /api/auth/deactivate
 *
 * Clears the activation cookie and deletes the local license vault.
 */
router.post("/auth/deactivate", (req: Request, res: Response) => {
  res.clearCookie(ACTIVATION_COOKIE, activationCookieOptions(ACTIVATION_TTL_MS, req));
  if (isDesktopEnvironment()) {
    clearDesktopLicense();
  }
  res.json({ success: true, status: "deactivated" });
});

export default router;
