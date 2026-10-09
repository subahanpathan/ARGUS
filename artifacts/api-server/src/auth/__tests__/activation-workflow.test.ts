import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import {
  evaluateActivation,
  verifyActivationToken,
  generateDownloadToken,
  verifyDownloadToken,
  consumeDownloadToken,
  saveDesktopLicense,
  verifyDesktopLicense,
  clearDesktopLicense,
  getDeviceFingerprint,
} from "../../lib/activation";

import { findInstaller, authorizeDownload } from "../../routes/desktop-download";

describe("Production-Ready ARGUS Activation & One-Time Download Workflow", () => {
  const TEST_KEY = "ARGUS-DEV-2026";
  const INVALID_KEY = "ARGUS-INVALID-KEY-9999";

  before(() => {
    process.env.ARGUS_DEV_ACCESS_KEY = TEST_KEY;
  });

  it("1. Backend evaluation rejects empty or invalid access keys with appropriate error codes", () => {
    const emptyResult = evaluateActivation("");
    assert.equal(emptyResult.ok, false);
    if (!emptyResult.ok) {
      assert.equal(emptyResult.code, "INVALID_ACCESS_KEY");
    }

    const invalidResult = evaluateActivation(INVALID_KEY);
    assert.equal(invalidResult.ok, false);
    if (!invalidResult.ok) {
      assert.equal(invalidResult.code, "INVALID_ACCESS_KEY");
    }
  });

  it("2. Backend evaluation accepts configured Access Key and returns signed activation & download tokens", () => {
    const validResult = evaluateActivation(TEST_KEY);
    assert.equal(validResult.ok, true);
    if (validResult.ok) {
      assert.ok(validResult.token, "Should issue signed activation token");
      assert.ok(validResult.downloadToken, "Should issue signed download token");
      assert.ok(verifyActivationToken(validResult.token), "Token should be cryptographically valid");
    }
  });

  it("3. Download tokens are one-time use and support HTTP Range resumes", () => {
    const dlToken = generateDownloadToken();
    assert.ok(dlToken, "Generates download token");

    // First check (initial download request)
    assert.equal(verifyDownloadToken(dlToken, { forResume: false }), true);

    // Consume the token (simulating download started)
    consumeDownloadToken(dlToken);

    // Subsequent non-resume attempt should fail (one-time download)
    assert.equal(verifyDownloadToken(dlToken, { forResume: false }), false);

    // Resume attempt within window should succeed
    assert.equal(verifyDownloadToken(dlToken, { forResume: true }), true);
  });

  it("4. Desktop License Vault saves hardware-bound tamper-evident certificate", () => {
    clearDesktopLicense();
    const fp = getDeviceFingerprint();
    assert.ok(fp, "Device fingerprint generated");

    const saved = saveDesktopLicense(TEST_KEY, null);
    assert.equal(saved, true, "License vault saved successfully");

    const check = verifyDesktopLicense();
    assert.equal(check.valid, true, "License vault verified as valid");

    clearDesktopLicense();
  });

  it("5. Desktop Installer discovery resolves existing ARGUS-Setup.exe binary", () => {
    const installer = findInstaller();
    assert.ok(installer, "Installer binary found");
    assert.ok(fs.existsSync(installer), "Installer file exists on disk");
    assert.ok(installer.endsWith("ARGUS-Setup.exe") || installer.endsWith("ARGUS.exe"), "Valid executable name");
  });

  it("6. Download authorization rejects unauthenticated callers and accepts valid tokens", () => {
    const mockReqUnauth: any = { headers: {}, query: {}, cookies: {} };
    const authUnauth = authorizeDownload(mockReqUnauth);
    assert.equal(authUnauth.ok, false, "Unauthenticated request rejected");

    const validDlToken = generateDownloadToken();
    const mockReqToken: any = { headers: {}, query: { token: validDlToken }, cookies: {} };
    const authToken = authorizeDownload(mockReqToken);
    assert.equal(authToken.ok, true, "Download token authorized");
  });
});
