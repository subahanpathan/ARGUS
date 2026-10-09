import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";

import {
  ACCESS_KEY_ENV,
  evaluateActivation,
  saveDesktopLicense,
  verifyDesktopLicense,
  clearDesktopLicense,
  getLicenseVaultPath,
  getDeviceFingerprint,
  revokeKey,
  isKeyRevoked,
  isKeyExpired,
} from "../../lib/activation";

const DEV_KEY = "ARGUS-DEV-2026";

let app: Express;
let server: Server;
let base: string;

before(async () => {
  process.env[ACCESS_KEY_ENV] = DEV_KEY;
  ({ default: app } = await import("../../app"));
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  clearDesktopLicense();
  delete process.env.ARGUS_DESKTOP;
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  process.env[ACCESS_KEY_ENV] = DEV_KEY;
  clearDesktopLicense();
  try {
    const revPath = path.join(os.homedir(), "AppData", "Local", "ARGUS", "revocations.json");
    if (fs.existsSync(revPath)) fs.unlinkSync(revPath);
  } catch {}
});

describe("Licensing Workflow Engine Tests", () => {
  it("evaluates valid access key successfully", () => {
    const outcome = evaluateActivation(DEV_KEY);
    assert.equal(outcome.ok, true);
    if (outcome.ok) {
      assert.ok(outcome.token);
      assert.ok(outcome.downloadToken);
      assert.ok(outcome.licenseId);
    }
  });

  it("evaluates expired access key and reports LICENSE_EXPIRED", () => {
    const outcome = evaluateActivation("ARGUS-EXPIRED-TEST");
    assert.equal(outcome.ok, false);
    if (!outcome.ok) {
      assert.equal(outcome.code, "LICENSE_EXPIRED");
    }
  });

  it("evaluates revoked access key and reports LICENSE_REVOKED", () => {
    const outcome = evaluateActivation("ARGUS-REVOKED-TEST");
    assert.equal(outcome.ok, false);
    if (!outcome.ok) {
      assert.equal(outcome.code, "LICENSE_REVOKED");
    }
  });

  it("can revoke a key dynamically and reject subsequent validations", () => {
    const tempKey = `ARGUS-REVOKE-${Date.now()}`;
    process.env.ARGUS_ACCESS_KEYS = tempKey;
    const initial = evaluateActivation(tempKey);
    assert.equal(initial.ok, true);

    revokeKey(tempKey);
    assert.equal(isKeyRevoked(tempKey), true);

    const afterRevoke = evaluateActivation(tempKey);
    assert.equal(afterRevoke.ok, false);
    if (!afterRevoke.ok) {
      assert.equal(afterRevoke.code, "LICENSE_REVOKED");
    }
  });

  it("creates, verifies, and binds license.vault to local device fingerprint", () => {
    clearDesktopLicense();
    const vaultPath = getLicenseVaultPath();
    assert.equal(fs.existsSync(vaultPath), false);

    const saved = saveDesktopLicense(DEV_KEY);
    assert.equal(saved, true);
    assert.equal(fs.existsSync(vaultPath), true);

    // Verify vault contents do NOT contain the plaintext access key
    const rawVault = fs.readFileSync(vaultPath, "utf8");
    assert.equal(rawVault.includes(DEV_KEY), false);

    // Verify license vault validity
    const check = verifyDesktopLicense();
    assert.equal(check.valid, true);

    clearDesktopLicense();
    assert.equal(fs.existsSync(vaultPath), false);
  });

  it("rejects license.vault if copied to a different machine (hardware mismatch anti-replay)", () => {
    saveDesktopLicense(DEV_KEY);
    const vaultPath = getLicenseVaultPath();

    // Tamper with device fingerprint to simulate copying the vault file to another machine
    const vaultData = JSON.parse(fs.readFileSync(vaultPath, "utf8"));
    vaultData.deviceFingerprint = "foreign_machine_fingerprint_deadbeef";
    fs.writeFileSync(vaultPath, JSON.stringify(vaultData, null, 2), "utf8");

    const check = verifyDesktopLicense();
    assert.equal(check.valid, false);
    assert.equal(check.reason, "TAMPERED_VAULT_SIGNATURE");
  });

  it("rejects tampered license.vault signature", () => {
    saveDesktopLicense(DEV_KEY);
    const vaultPath = getLicenseVaultPath();

    const vaultData = JSON.parse(fs.readFileSync(vaultPath, "utf8"));
    vaultData.signature = "tampered_fake_signature";
    fs.writeFileSync(vaultPath, JSON.stringify(vaultData, null, 2), "utf8");

    const check = verifyDesktopLicense();
    assert.equal(check.valid, false);
    assert.equal(check.reason, "TAMPERED_VAULT_SIGNATURE");
  });
});

describe("Desktop In-App Startup Activation Persistence Endpoints", () => {
  it("rejects expired key via POST /api/auth/activate with 401", async () => {
    const res = await fetch(`${base}/api/auth/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accessKey: "ARGUS-EXPIRED-TEST" }),
    });
    assert.equal(res.status, 401);
    const json = (await res.json()) as { code: string };
    assert.equal(json.code, "LICENSE_EXPIRED");
  });

  it("rejects revoked key via POST /api/auth/activate with 403", async () => {
    const res = await fetch(`${base}/api/auth/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accessKey: "ARGUS-REVOKED-TEST" }),
    });
    assert.equal(res.status, 403);
    const json = (await res.json()) as { code: string };
    assert.equal(json.code, "LICENSE_REVOKED");
  });

  it("persists license in desktop mode and grants access without cookie on startup", async () => {
    process.env.ARGUS_DESKTOP = "1";
    try {
      // 1. Activate in desktop mode
      const activateRes = await fetch(`${base}/api/auth/activate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ accessKey: DEV_KEY }),
      });
      assert.equal(activateRes.status, 200);
      const actJson = (await activateRes.json()) as { isDesktop: boolean; success: boolean };
      assert.equal(actJson.success, true);
      assert.equal(actJson.isDesktop, true);

      // Verify vault was written to disk
      assert.equal(fs.existsSync(getLicenseVaultPath()), true);

      // 2. Simulate application restart: query status WITHOUT cookie or Authorization header
      const statusRes = await fetch(`${base}/api/auth/status`);
      assert.equal(statusRes.status, 200);
      const statusJson = (await statusRes.json()) as { activated: boolean; isDesktop: boolean };
      assert.equal(statusJson.activated, true);
      assert.equal(statusJson.isDesktop, true);

      // 3. Deactivate in desktop mode clears vault
      const deactRes = await fetch(`${base}/api/auth/deactivate`, { method: "POST" });
      assert.equal(deactRes.status, 200);
      assert.equal(fs.existsSync(getLicenseVaultPath()), false);

      // 4. Query status again -> now reports activated: false
      const postDeactRes = await fetch(`${base}/api/auth/status`);
      assert.equal(postDeactRes.status, 200);
      const postDeactJson = (await postDeactRes.json()) as { activated: boolean };
      assert.equal(postDeactJson.activated, false);
    } finally {
      delete process.env.ARGUS_DESKTOP;
      clearDesktopLicense();
    }
  });
});
