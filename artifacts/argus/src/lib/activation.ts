/**
 * ARGUS activation — frontend client.
 *
 * Phase A replaces the public registration flow with an Access Key gate. The
 * key is validated on the server (`POST /api/auth/activate`) and by nothing
 * else: there is deliberately no comparison in this bundle, so the key cannot
 * be recovered by reading the shipped JavaScript.
 *
 * What *is* stored locally is a non-secret activation marker plus the server's
 * HttpOnly activation cookie. The marker only exists so a refresh does not flash
 * the activation screen; `GET /api/auth/status` remains the authority, and a
 * server that says "not activated" wins over the marker.
 *
 * The raw access key is never written to localStorage, sessionStorage, a cookie,
 * or the console.
 */

/** Route that requires an activated installation. */
export const ACTIVATION_ROUTE = "/activate";

/** localStorage key holding the safe activation marker. */
export const ACTIVATION_MARKER_KEY = "argus.activation.v1";

export const ACTIVATION_MESSAGES = {
  empty: "Enter your ARGUS Access Key to activate this installation.",
  invalid: "Invalid ARGUS Access Key.",
  unavailable: "Unable to contact the ARGUS activation service. Please try again.",
} as const;

export type ActivationFailure = "empty" | "invalid" | "unavailable";

export type ActivationResult =
  | { ok: true }
  | { ok: false; reason: ActivationFailure };

/** Server response shape for `POST /api/auth/activate`. */
type ActivateResponseBody = { success?: boolean; status?: string; code?: string };

/**
 * The stored marker. Contains no secret — only a status and a timestamp, so it
 * is safe to inspect in devtools and useless to an attacker.
 */
type ActivationMarker = { status: "activated"; activatedAt: string };

function isMarker(value: unknown): value is ActivationMarker {
  if (!value || typeof value !== "object") return false;
  const marker = value as Partial<ActivationMarker>;
  return marker.status === "activated" && typeof marker.activatedAt === "string";
}

function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    // Private-mode / storage-disabled browsers still activate normally.
    return null;
  }
}

function writeStorage(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Non-fatal: the server cookie still carries the activation.
  }
}

function removeStorage(key: string): void {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Non-fatal.
  }
}

/** True when this browser holds a local activation marker. */
export function hasActivationMarker(): boolean {
  const raw = readStorage(ACTIVATION_MARKER_KEY);
  if (!raw) return false;
  try {
    return isMarker(JSON.parse(raw));
  } catch {
    // A malformed marker is treated as absent and cleaned up.
    removeStorage(ACTIVATION_MARKER_KEY);
    return false;
  }
}

/** Record activation locally. Stores no part of the access key. */
export function writeActivationMarker(): void {
  const marker: ActivationMarker = { status: "activated", activatedAt: new Date().toISOString() };
  writeStorage(ACTIVATION_MARKER_KEY, JSON.stringify(marker));
}

/** Forget the local activation marker. */
export function clearActivationMarker(): void {
  removeStorage(ACTIVATION_MARKER_KEY);
}

/**
 * Ask the server whether this installation is activated.
 *
 * `null` means "could not tell" — the API is down or erroring. That is
 * deliberately distinct from `false`, so a transient backend outage does not
 * lock an activated operator out of the workspace.
 */
export async function fetchActivationStatus(): Promise<boolean | null> {
  try {
    const response = await fetch("/api/auth/status", {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { activated?: unknown };
    return typeof body.activated === "boolean" ? body.activated : null;
  } catch {
    return null;
  }
}

/**
 * Submit an access key for validation.
 *
 * Maps every failure to one of three user-facing states. Network faults and
 * unexpected payloads both surface as `unavailable` rather than leaking backend
 * detail into the UI.
 */
export async function activate(accessKey: string): Promise<ActivationResult> {
  const key = accessKey.trim();
  if (key.length === 0) return { ok: false, reason: "empty" };

  let response: Response;
  try {
    response = await fetch("/api/auth/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ accessKey: key }),
    });
  } catch {
    return { ok: false, reason: "unavailable" };
  }

  let body: ActivateResponseBody | null = null;
  try {
    body = (await response.json()) as ActivateResponseBody;
  } catch {
    body = null;
  }

  if (response.ok && body?.success === true) return { ok: true };

  if (response.status === 503) return { ok: false, reason: "unavailable" };
  if (response.status === 400 || response.status === 401 || response.status === 403) {
    return { ok: false, reason: "invalid" };
  }
  return { ok: false, reason: "unavailable" };
}

/**
 * Deactivate this installation: clear the server cookie and the local marker.
 *
 * Best-effort — if the API is unreachable the local marker is still cleared, so
 * the UI returns to the activation screen either way.
 */
export async function deactivate(): Promise<void> {
  clearActivationMarker();
  try {
    await fetch("/api/auth/deactivate", { method: "POST", credentials: "same-origin" });
  } catch {
    // The cookie is cleared server-side on the next successful call.
  }
}
