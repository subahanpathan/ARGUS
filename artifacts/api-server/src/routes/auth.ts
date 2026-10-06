/**
 * ARGUS activation endpoints.
 *
 * There is no register or create-account endpoint. The only way into the
 * product is `POST /api/auth/activate` with a valid ARGUS Access Key.
 *
 * Responses are deliberately terse. A caller learns whether the key was
 * accepted, never what the configured key is and never why a check failed
 * internally. `GET /api/auth/status` exists so the UI can reconcile a refresh
 * against the server instead of trusting browser storage on its own.
 */

import { Router, type IRouter, type Request, type Response } from "express";

import {
  ACTIVATION_COOKIE,
  ACTIVATION_TTL_MS,
  activationCookieOptions,
  evaluateActivation,
  verifyActivationToken,
} from "../lib/activation";
import { logger } from "../lib/logger";

const router: IRouter = Router();

type ActivateBody = { accessKey?: unknown };

/**
 * POST /api/auth/activate
 *
 * 200 `{ success: true, status: "activated" }`
 * 400 `{ success: false, code: "INVALID_ACCESS_KEY" }`   — empty key
 * 401 `{ success: false, code: "INVALID_ACCESS_KEY" }`   — wrong key
 * 503 `{ success: false, code: "ACTIVATION_UNAVAILABLE" }` — server has no key
 */
router.post("/auth/activate", (req: Request, res: Response) => {
  const body = (req.body ?? {}) as ActivateBody;
  const outcome = evaluateActivation(body.accessKey);

  if (!outcome.ok) {
    // Note the absence of the submitted value: logging it would defeat the
    // point of the gate.
    logger.warn(
      { scope: "activation", code: outcome.code, remote: req.socket?.remoteAddress },
      "rejected ARGUS activation attempt",
    );
    const status = outcome.code === "ACTIVATION_UNAVAILABLE" ? 503 : 401;
    res.status(status).json({ success: false, code: outcome.code });
    return;
  }

  res.cookie(ACTIVATION_COOKIE, outcome.token, activationCookieOptions(ACTIVATION_TTL_MS));
  logger.info({ scope: "activation" }, "ARGUS activation accepted");
  res.json({ success: true, status: "activated" });
});

/**
 * GET /api/auth/status
 *
 * Authoritative answer to "is this installation activated?". Reads only the
 * HttpOnly activation cookie, so it cannot be forged from browser storage.
 */
router.get("/auth/status", (req: Request, res: Response) => {
  res.json({ activated: verifyActivationToken(req.cookies?.[ACTIVATION_COOKIE]) });
});

/**
 * POST /api/auth/deactivate
 *
 * Clears the activation cookie. Called when the operator deactivates the
 * installation from the sidebar.
 */
router.post("/auth/deactivate", (_req: Request, res: Response) => {
  res.clearCookie(ACTIVATION_COOKIE, activationCookieOptions(ACTIVATION_TTL_MS));
  res.json({ success: true, status: "deactivated" });
});

export default router;
