import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";

import { ACCESS_KEY_ENV, ACTIVATION_COOKIE } from "../../lib/activation";

const DEV_KEY = "argus-test-access-key-4f2b";

let app: Express;
let server: Server;
let base: string;

type ActivateResponse = { success: boolean; status?: string; code?: string };

async function postActivate(accessKey?: unknown): Promise<{ status: number; body: ActivateResponse; raw: string; setCookie: string }> {
  const response = await fetch(`${base}/api/auth/activate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(accessKey === undefined ? {} : { accessKey }),
  });
  const raw = await response.text();
  return {
    status: response.status,
    body: raw ? JSON.parse(raw) : null,
    raw,
    setCookie: response.headers.get("set-cookie") ?? "",
  };
}

async function getStatus(cookie?: string): Promise<{ status: number; body: { activated: boolean } }> {
  const response = await fetch(`${base}/api/auth/status`, {
    headers: cookie ? { Cookie: cookie } : {},
  });
  return { status: response.status, body: (await response.json()) as { activated: boolean } };
}

/** Pull the activation cookie out of a Set-Cookie header as a request Cookie. */
function cookiePair(setCookie: string): string {
  return setCookie.split(";")[0];
}

before(async () => {
  process.env[ACCESS_KEY_ENV] = DEV_KEY;
  ({ default: app } = await import("../../app"));
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  process.env[ACCESS_KEY_ENV] = DEV_KEY;
});

describe("POST /api/auth/activate", () => {
  it("rejects an empty access key", async () => {
    const { status, body } = await postActivate("");
    assert.equal(status, 401);
    assert.deepEqual(body, { success: false, code: "INVALID_ACCESS_KEY" });
  });

  it("rejects a missing access key", async () => {
    const { status, body } = await postActivate();
    assert.equal(status, 401);
    assert.deepEqual(body, { success: false, code: "INVALID_ACCESS_KEY" });
  });

  it("rejects a non-string access key", async () => {
    const { status, body } = await postActivate({ toString: () => DEV_KEY });
    assert.equal(status, 401);
    assert.equal(body.code, "INVALID_ACCESS_KEY");
  });

  it("rejects an invalid access key", async () => {
    const { status, body, setCookie } = await postActivate("not-the-key");
    assert.equal(status, 401);
    assert.deepEqual(body, { success: false, code: "INVALID_ACCESS_KEY" });
    assert.equal(setCookie, "");
  });

  it("rejects a key that is a prefix of the real key", async () => {
    const { status, body } = await postActivate(DEV_KEY.slice(0, -1));
    assert.equal(status, 401);
    assert.equal(body.code, "INVALID_ACCESS_KEY");
  });

  it("accepts the configured development key", async () => {
    const { status, body } = await postActivate(DEV_KEY);
    assert.equal(status, 200);
    assert.deepEqual(body, { success: true, status: "activated" });
  });

  it("tolerates surrounding whitespace on the submitted key", async () => {
    const { status, body } = await postActivate(`  ${DEV_KEY}\n`);
    assert.equal(status, 200);
    assert.equal(body.success, true);
  });

  it("never returns the configured key in the response body", async () => {
    const { raw } = await postActivate(DEV_KEY);
    assert.equal(raw.includes(DEV_KEY), false);
  });

  it("never returns the configured key in a response header", async () => {
    const { setCookie } = await postActivate(DEV_KEY);
    assert.equal(setCookie.includes(DEV_KEY), false);
  });

  it("sets an HttpOnly activation cookie that does not carry the key", async () => {
    const { setCookie } = await postActivate(DEV_KEY);
    assert.match(setCookie, new RegExp(`${ACTIVATION_COOKIE}=`));
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /SameSite=Strict/i);
    assert.equal(setCookie.includes(DEV_KEY), false);
  });

  it("reports ACTIVATION_UNAVAILABLE when no key is configured", async () => {
    delete process.env[ACCESS_KEY_ENV];
    const { status, body, setCookie } = await postActivate("anything");
    assert.equal(status, 503);
    assert.deepEqual(body, { success: false, code: "ACTIVATION_UNAVAILABLE" });
    assert.equal(setCookie, "");
  });
});

describe("GET /api/auth/status", () => {
  it("reports not activated without a cookie", async () => {
    const { status, body } = await getStatus();
    assert.equal(status, 200);
    assert.deepEqual(body, { activated: false });
  });

  it("reports not activated for a forged cookie", async () => {
    const { body } = await getStatus(`${ACTIVATION_COOKIE}=v1.${Date.now()}.deadbeef`);
    assert.equal(body.activated, false);
  });

  it("reports not activated for a malformed cookie", async () => {
    const { body } = await getStatus(`${ACTIVATION_COOKIE}=garbage`);
    assert.equal(body.activated, false);
  });

  it("reports activated for a cookie issued by a successful activation", async () => {
    const { setCookie } = await postActivate(DEV_KEY);
    const { body } = await getStatus(cookiePair(setCookie));
    assert.deepEqual(body, { activated: true });
  });

  it("keeps activation across a restart because the token is self-describing", async () => {
    const { setCookie } = await postActivate(DEV_KEY);
    const cookie = cookiePair(setCookie);

    // A fresh import of the module graph stands in for an API restart: there is
    // no in-memory session table that could have survived by accident.
    const { verifyActivationToken } = await import(`../../lib/activation?restart=${Date.now()}`);
    const token = cookie.slice(cookie.indexOf("=") + 1);
    assert.equal(verifyActivationToken(token), true);
  });

  it("invalidates an existing cookie once the key is rotated", async () => {
    const { setCookie } = await postActivate(DEV_KEY);
    const cookie = cookiePair(setCookie);

    process.env[ACCESS_KEY_ENV] = "a-completely-different-key";
    const { body } = await getStatus(cookie);
    assert.deepEqual(body, { activated: false });
  });
});

describe("POST /api/auth/deactivate", () => {
  it("clears the activation cookie", async () => {
    const { setCookie } = await postActivate(DEV_KEY);
    assert.notEqual(setCookie, "");

    const response = await fetch(`${base}/api/auth/deactivate`, { method: "POST" });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true, status: "deactivated" });

    const cleared = response.headers.get("set-cookie") ?? "";
    assert.match(cleared, new RegExp(`${ACTIVATION_COOKIE}=;`));
    assert.match(cleared, /HttpOnly/i);
  });
});

describe("registration is not reachable", () => {
  const gone = ["/api/auth/register", "/api/auth/signup", "/api/auth/login"];

  for (const route of gone) {
    it(`has no endpoint at ${route}`, async () => {
      const response = await fetch(`${base}${route}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "a@b.test", password: "whatever123" }),
      });
      assert.ok(response.status === 404 || response.status === 405, `expected 404/405, got ${response.status}`);
    });
  }
});
