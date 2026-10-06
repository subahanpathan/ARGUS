/**
 * Local-agent ingest guard.
 *
 * The endpoint agent posts telemetry to this API from the same machine. Those
 * ingest routes accept data that describes the host and can queue commands for
 * the agent, so they must not be reachable from off-box.
 *
 * Two layers, both cheap:
 *
 * 1. **Loopback only** — the peer address must be a loopback address. A request
 *    forwarded by a dev proxy (`X-Forwarded-For`) or arriving on a LAN interface
 *    is rejected, so a browser on another machine cannot post fake telemetry or
 *    queue a scan.
 * 2. **Optional shared secret** — when `ARGUS_AGENT_TOKEN` is set, the agent must
 *    present the same value in `X-Argus-Agent-Token`.
 *
 * Read-only monitoring endpoints stay open: the UI needs them, and exposing them
 * reveals nothing the endpoint has not already published.
 */

import type { NextFunction, Request, Response } from "express";
import { logger } from "../lib/logger";

/** Loopback addresses in IPv4, IPv6-mapped IPv4, and IPv6. */
const LOOPBACK_ADDRESSES = new Set([
  "127.0.0.1",
  "::1",
  "::ffff:127.0.0.1",
  "0:0:0:0:0:0:0:1",
]);

/**
 * Extract the peer address. `X-Forwarded-For` is deliberately *not* trusted as
 * the peer identity, but when present its first hop must also be loopback,
 * otherwise a proxied request from elsewhere is refused.
 */
function peerAddresses(req: Request): string[] {
  const addresses: string[] = [];
  const socketAddress = req.socket?.remoteAddress;
  if (socketAddress) addresses.push(socketAddress);

  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    for (const part of forwarded.split(",")) {
      const candidate = part.trim();
      if (candidate) addresses.push(candidate);
    }
  }
  return addresses;
}

function isLoopback(address: string): boolean {
  const normalized = address.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (LOOPBACK_ADDRESSES.has(normalized)) return true;
  // Any 127.0.0.0/8 address is loopback.
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized)) return true;
  return false;
}

/** Express middleware enforcing loopback + optional token on ingest routes. */
export function requireLocalAgent(req: Request, res: Response, next: NextFunction): void {
  const addresses = peerAddresses(req);
  if (addresses.length === 0 || !addresses.every(isLoopback)) {
    logger.warn(
      { remote: addresses.join(","), url: req.url },
      "rejected non-loopback agent ingest request",
    );
    res.status(403).json({
      error: "Local agent access only",
      detail: "Endpoint ingest routes accept requests from the loopback interface only.",
    });
    return;
  }

  const expected = process.env.ARGUS_AGENT_TOKEN?.trim();
  if (expected) {
    const provided = req.headers["x-argus-agent-token"];
    const token = typeof provided === "string" ? provided : "";
    if (token !== expected) {
      logger.warn({ url: req.url }, "rejected agent ingest request with invalid token");
      res.status(401).json({ error: "Invalid agent token" });
      return;
    }
  }

  next();
}

export default requireLocalAgent;
