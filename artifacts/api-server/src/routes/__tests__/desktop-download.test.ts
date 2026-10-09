import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";
import { ACCESS_KEY_ENV, ACTIVATION_COOKIE } from "../../lib/activation";

const TEST_KEY = "argus-test-key-secure-download";

let app: Express;
let server: Server;
let base: string;
let validCookie: string;
let validDownloadToken: string;

before(async () => {
  process.env[ACCESS_KEY_ENV] = TEST_KEY;
  ({ default: app } = await import("../../app"));
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  // Perform activation to get valid cookie and download token
  const activateRes = await fetch(`${base}/api/auth/activate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ accessKey: TEST_KEY }),
  });
  assert.equal(activateRes.status, 200);
  const data = (await activateRes.json()) as { success: boolean; downloadToken: string };
  assert.equal(data.success, true);
  validDownloadToken = data.downloadToken;
  validCookie = (activateRes.headers.get("set-cookie") ?? "").split(";")[0];
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("Desktop Installer Download Endpoints", () => {
  it("rejects unauthenticated GET /api/desktop/download with 401", async () => {
    const res = await fetch(`${base}/api/desktop/download`);
    assert.equal(res.status, 401);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, "ACTIVATION_REQUIRED");
  });

  it("rejects unauthenticated HEAD /api/desktop/download with 401", async () => {
    const res = await fetch(`${base}/api/desktop/download`, { method: "HEAD" });
    assert.equal(res.status, 401);
  });

  it("allows download with valid download token in query string", async () => {
    const res = await fetch(`${base}/api/desktop/download?token=${validDownloadToken}`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-disposition") || "", /attachment;\s*filename="ARGUS-Setup\.exe"/i);
    assert.equal(res.headers.get("accept-ranges"), "bytes");

    // Read a slice to verify stream
    const reader = res.body?.getReader();
    const chunk = await reader?.read();
    assert.ok(chunk?.value && chunk.value.length > 0, "Installer stream contains data");
    await reader?.cancel();
  });

  it("allows download with activation cookie", async () => {
    const res = await fetch(`${base}/api/desktop/download`, {
      headers: { Cookie: validCookie },
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-disposition") || "", /attachment;\s*filename="ARGUS-Setup\.exe"/i);
  });

  it("supports HTTP Range requests for interrupted and resumable downloads", async () => {
    const res = await fetch(`${base}/api/desktop/download?token=${validDownloadToken}`, {
      headers: { Range: "bytes=0-1023" },
    });
    assert.equal(res.status, 206);
    assert.match(res.headers.get("content-range") || "", /^bytes 0-1023\/\d+/);
    assert.equal(res.headers.get("content-length"), "1024");
    assert.match(res.headers.get("content-disposition") || "", /attachment;\s*filename="ARGUS-Setup\.exe"/i);

    const buf = await res.arrayBuffer();
    assert.equal(buf.byteLength, 1024);
  });

  it("GET /api/downloads/argus-windows aliases the installer download with auth", async () => {
    const res = await fetch(`${base}/api/downloads/argus-windows`, {
      method: "HEAD",
      headers: { Cookie: validCookie },
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-disposition") || "", /attachment;\s*filename="ARGUS-Setup\.exe"/i);
  });

  it("returns 404 when installer is unavailable even if authorized", async () => {
    process.env.ARGUS_INSTALLER_PATH = "nonexistent-installer-file.exe";
    try {
      const res = await fetch(`${base}/api/desktop/download`, {
        headers: { Cookie: validCookie },
      });
      assert.equal(res.status, 404);
      const json = (await res.json()) as { code: string };
      assert.equal(json.code, "INSTALLER_NOT_FOUND");
    } finally {
      delete process.env.ARGUS_INSTALLER_PATH;
    }
  });
});

