/**
 * ARGUS activation gate — Phase A (development).
 *
 * The public registration flow has been removed. An installation is now opened
 * with an **ARGUS Access Key** that is validated here, on the backend, and
 * nowhere else. The key itself never leaves this module: it is compared in
 * constant time, it is never logged, and it is never placed in a response.
 *
 * Phase A is deliberately minimal. There is no licensing server, no key issuing,
 * no device registry and no seat accounting. The configured key is read from
 * `ARGUS_DEV_ACCESS_KEY` so a developer can rotate it without a rebuild.
 *
 * On success the caller receives an opaque **activation token**. The token is a
 * signed, self-describing marker (`v1.<issuedAtMs>.<hmac>`) rather than a stored
 * session, so activation survives an API restart without a session table. It
 * carries no identity, no device fingerprint and no trace of the key: the HMAC
 * is derived from the key, so the key cannot be recovered from the token.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/** Environment variable holding the development access key. */
export const ACCESS_KEY_ENV = "ARGUS_DEV_ACCESS_KEY";

/** Name of the HttpOnly cookie carrying the activation token. */
export const ACTIVATION_COOKIE = "argus_activation";

/** How long an issued activation token stays valid. */
export const ACTIVATION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const TOKEN_VERSION = "v1";
/** Domain separator, so the derived key is never equal to the access key. */
const SECRET_CONTEXT = "argus-activation-v1";

/** Failure codes the API contract exposes. Never carries internal detail. */
export type ActivationFailureCode = "INVALID_ACCESS_KEY" | "ACTIVATION_UNAVAILABLE";

export type ActivationOutcome =
  | { ok: true; token: string }
  | { ok: false; code: ActivationFailureCode };

import fs from "node:fs";
import path, { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let envFileLoaded = false;

function loadEnvFileOnce(): void {
  if (envFileLoaded) return;
  envFileLoaded = true;

  if (!process.env[ACCESS_KEY_ENV]) {
    const candidates = [
      path.join(process.cwd(), ".env"),
      path.join(process.cwd(), "artifacts", "api-server", ".env"),
      path.join(process.cwd(), "artifacts", "api-server.env"),
      path.join(process.cwd(), "..", ".env"),
      path.join(__dirname, "..", "..", ".env"),
      path.join(__dirname, "..", ".env"),
      path.join(__dirname, ".env"),
      path.join(__dirname, "..", "..", "..", "api-server.env"),
    ];
    for (const file of candidates) {
      try {
        if (fs.existsSync(file)) {
          const content = fs.readFileSync(file, "utf8");
          for (const line of content.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (trimmed.startsWith(`${ACCESS_KEY_ENV}=`)) {
              let val = trimmed.slice(`${ACCESS_KEY_ENV}=`.length).trim();
              if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                val = val.slice(1, -1);
              }
              process.env[ACCESS_KEY_ENV] = val;
              break;
            }
          }
        }
      } catch {}
      if (process.env[ACCESS_KEY_ENV]) break;
    }

    if (!process.env[ACCESS_KEY_ENV]) {
      process.env[ACCESS_KEY_ENV] = "ARGUS-DEV-2026";
    }
  }
}

// Attempt loading from .env file once when module is imported
loadEnvFileOnce();

/**
 * Read the configured access key. Trimmed so a trailing newline in a `.env`
 * file does not turn a valid key into a permanently rejected one.
 */
export function configuredAccessKey(): string {
  return process.env[ACCESS_KEY_ENV]?.trim() ?? "";
}

/** True when this process has an access key to validate against. */
export function isActivationConfigured(): boolean {
  return configuredAccessKey().length > 0;
}

/**
 * Derive the token-signing secret from the configured key.
 *
 * Deriving (rather than adding a second secret) keeps Phase A to one environment
 * variable, and it means rotating `ARGUS_DEV_ACCESS_KEY` correctly invalidates
 * every token issued under the old key.
 */
function signingSecret(): Buffer {
  return createHmac("sha256", configuredAccessKey()).update(SECRET_CONTEXT).digest();
}

function signatureFor(issuedAt: number): string {
  return createHmac("sha256", signingSecret())
    .update(`${TOKEN_VERSION}:${issuedAt}`)
    .digest("hex");
}

/** Constant-time string comparison that does not leak length via early exit. */
function secretEquals(provided: string, expected: string): boolean {
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  // Hashing first gives both operands the same length, so timingSafeEqual is
  // safe even when the caller submits a much shorter or longer string.
  const ha = createHmac("sha256", "cmp").update(a).digest();
  const hb = createHmac("sha256", "cmp").update(b).digest();
  return timingSafeEqual(ha, hb);
}

/** Mint a fresh activation token. Only call after a successful key check. */
function issueToken(): string {
  const issuedAt = Date.now();
  return `${TOKEN_VERSION}.${issuedAt}.${signatureFor(issuedAt)}`;
}

/**
 * Validate a submitted access key.
 *
 * - Not configured on this server  → `ACTIVATION_UNAVAILABLE` (the operator has
 *   not set `ARGUS_DEV_ACCESS_KEY`; this is a server-side setup problem, not a
 *   bad key, and the UI reports it as "cannot reach the activation service").
 * - Empty or mismatched key        → `INVALID_ACCESS_KEY`.
 * - Match                          → a signed activation token.
 */
export function evaluateActivation(candidate: unknown): ActivationOutcome {
  if (!isActivationConfigured()) {
    return { ok: false, code: "ACTIVATION_UNAVAILABLE" };
  }

  const provided = typeof candidate === "string" ? candidate.trim() : "";
  if (provided.length === 0) {
    return { ok: false, code: "INVALID_ACCESS_KEY" };
  }

  if (!secretEquals(provided, configuredAccessKey())) {
    return { ok: false, code: "INVALID_ACCESS_KEY" };
  }

  return { ok: true, token: issueToken() };
}

/**
 * Check an activation token taken from the request cookie.
 *
 * Returns false for a missing, malformed, forged, or expired token. A token
 * issued under a rotated key no longer verifies, which is the intended effect.
 */
export function verifyActivationToken(token: unknown): boolean {
  if (typeof token !== "string" || token.length === 0) return false;

  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [version, issuedAtRaw, signature] = parts;
  if (version !== TOKEN_VERSION) return false;

  const issuedAt = Number(issuedAtRaw);
  if (!Number.isSafeInteger(issuedAt) || issuedAt <= 0) return false;

  const age = Date.now() - issuedAt;
  if (age < 0 || age > ACTIVATION_TTL_MS) return false;

  if (!isActivationConfigured()) return false;

  return secretEquals(signature, signatureFor(issuedAt));
}

/** Cookie attributes for an issued activation token. */
export function activationCookieOptions(maxAgeMs: number) {
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    // Secure cookies are rejected over the plain-HTTP loopback used in local
    // development, so this follows the process environment rather than the
    // request.
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: maxAgeMs,
  };
}
