import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";

let app: Express;
let server: Server;
let base: string;

before(async () => {
  ({ default: app } = await import("../../app"));
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("Desktop Installer Download Endpoints", () => {
  it("HEAD /api/desktop/download returns 200 with attachment headers", async () => {
    const res = await fetch(`${base}/api/desktop/download`, { method: "HEAD" });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-disposition") || "", /attachment;\s*filename="ARGUS-Setup\.exe"/i);
  });

  it("GET /api/desktop/download returns 200 with application/octet-stream", async () => {
    const res = await fetch(`${base}/api/desktop/download`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "application/octet-stream");
    assert.match(res.headers.get("content-disposition") || "", /attachment;\s*filename="ARGUS-Setup\.exe"/i);

    // Read the first 1KB to ensure it streams valid binary data
    const reader = res.body?.getReader();
    const chunk = await reader?.read();
    assert.ok(chunk?.value && chunk.value.length > 0, "Installer stream contains data");
    await reader?.cancel();
  });

  it("GET /api/downloads/argus-windows aliases the installer download", async () => {
    const res = await fetch(`${base}/api/downloads/argus-windows`, { method: "HEAD" });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-disposition") || "", /attachment;\s*filename="ARGUS-Setup\.exe"/i);
  });

  it("returns 404 when installer is unavailable", async () => {
    process.env.ARGUS_INSTALLER_PATH = "";
    try {
      const res = await fetch(`${base}/api/desktop/download`);
      assert.equal(res.status, 404);
      const json = await res.json() as { error: string };
      assert.equal(json.error, "ARGUS Windows installer is not available");

      const headRes = await fetch(`${base}/api/desktop/download`, { method: "HEAD" });
      assert.equal(headRes.status, 404);
    } finally {
      delete process.env.ARGUS_INSTALLER_PATH;
    }
  });
});
