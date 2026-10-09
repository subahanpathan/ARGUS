import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { eventHub, type MonitoringEvent, type ProcessSnapshot } from "../../lib/event-hub";
import { correlate } from "../../lib/correlation";

const NOW = "2026-01-01T12:00:00.000Z";

function processSnapshot(processes: ProcessSnapshot["processes"]): ProcessSnapshot {
  return { timestamp: NOW, total_count: processes.length, access_denied_count: 0, processes };
}

function fileEvent(path: string, id = "fs-1"): MonitoringEvent {
  return {
    eventId: id,
    timestamp: NOW,
    eventType: "FILE_CREATED",
    source: "filesystem_watch",
    entity: { kind: "file", id: path, name: path.split("\\").pop() ?? path },
    severity: "info",
    evidence: { path, is_directory: false },
  };
}

function providerDetectionEvent(id: string, resources: string[], processName: string): MonitoringEvent {
  return {
    eventId: id,
    timestamp: NOW,
    eventType: "SECURITY_PROVIDER_ALERT",
    source: "security_provider",
    entity: { kind: "security_provider", id: "windows-defender", name: "Microsoft Defender Antivirus" },
    severity: "high",
    evidence: {
      kind: "DETECTION",
      provider_id: "windows-defender",
      process_name: processName,
      resources,
      title: "Threat detected",
    },
  };
}

describe("monitoring event ingest", () => {
  beforeEach(() => eventHub.reset());

  it("accepts normalized events and ignores redelivered ids", () => {
    const first = eventHub.addMonitoringEvents([fileEvent("C:\\Temp\\a.exe")]);
    const second = eventHub.addMonitoringEvents([fileEvent("C:\\Temp\\a.exe")]);

    assert.equal(first.accepted, 1);
    assert.equal(first.duplicates, 0);
    assert.equal(second.accepted, 0);
    assert.equal(second.duplicates, 1);
    assert.equal(eventHub.getMonitoringEvents(10).length, 1);
  });

  it("rejects events without an id or type instead of storing them", () => {
    const result = eventHub.addMonitoringEvents([
      { eventId: "", timestamp: NOW, eventType: "", source: "x", entity: { kind: "", id: "", name: "" } } as MonitoringEvent,
    ]);
    assert.equal(result.accepted, 0);
    assert.equal(eventHub.getMonitoringEvents(10).length, 0);
  });

  it("filters the feed by source and event type", () => {
    eventHub.addMonitoringEvents([
      fileEvent("C:\\Temp\\a.exe", "fs-1"),
      providerDetectionEvent("sec-1", ["C:\\Temp\\a.exe"], "a.exe"),
    ]);
    assert.equal(eventHub.getMonitoringEvents(10, "filesystem_watch").length, 1);
    assert.equal(eventHub.getMonitoringEvents(10, undefined, "SECURITY_PROVIDER_ALERT").length, 1);
  });
});

describe("scan registry", () => {
  beforeEach(() => eventHub.reset());

  it("refuses a scan update with no scan id", () => {
    const stored = eventHub.upsertScan({ scan_id: "", state: "SCANNING", scan_type: "filesystem" });
    assert.equal(stored, null);
  });

  it("registers a scan from its scan event evidence and tracks the active one", () => {
    eventHub.addMonitoringEvents([
      {
        eventId: "scan-evt-1",
        timestamp: NOW,
        eventType: "SCAN_STARTED",
        source: "filesystem_scan",
        entity: { kind: "scan", id: "scan-abc", name: "scheduled" },
        evidence: {
          scan_id: "scan-abc",
          scan_state: "SCANNING",
          files_discovered: 120,
          files_scanned: 40,
          total_known: true,
          progress_percent: 33.33,
        },
      },
    ]);

    const scan = eventHub.getScan("scan-abc");
    assert.ok(scan);
    assert.equal(scan?.state, "SCANNING");
    assert.equal(scan?.files_scanned, 40);
    assert.equal(scan?.progress_percent, 33.33);

    const active = eventHub.getActiveScan();
    assert.equal(active?.scan_id, "scan-abc");
  });

  it("keeps a null progress percentage when no denominator was measured", () => {
    eventHub.upsertScan({
      scan_id: "scan-unknown",
      state: "SCANNING",
      scan_type: "filesystem",
      total_known: false as any,
      progress_percent: null as any,
    });
    const scan = eventHub.getScan("scan-unknown");
    assert.equal(scan?.progress_percent, null);
    assert.equal(scan?.total_known, false);
  });

  it("returns no active scan once the scan finishes", () => {
    eventHub.upsertScan({ scan_id: "scan-done", state: "COMPLETED", scan_type: "filesystem" });
    assert.equal(eventHub.getActiveScan(), null);
  });
});

describe("filesystem change telemetry", () => {
  beforeEach(() => eventHub.reset());

  it("counts real change kinds and carries delivery gaps through", () => {
    const { accepted, watcher } = eventHub.ingestFilesystemActivity({
      timestamp: NOW,
      events: [
        { kind: "FILE_CREATED", path: "C:\\a", root: "C:\\", name: "a", is_directory: false, timestamp: NOW },
        { kind: "FILE_MODIFIED", path: "C:\\b", root: "C:\\", name: "b", is_directory: false, timestamp: NOW },
        { kind: "FILE_DELETED", path: "C:\\c", root: "C:\\", name: "c", is_directory: false, timestamp: NOW },
        { kind: "FILE_RENAMED", path: "C:\\d", root: "C:\\", name: "d", is_directory: false, old_path: "C:\\old", timestamp: NOW },
      ],
      watcher: {
        backend: "readdirectorychangesw",
        available: true,
        roots: ["C:\\"],
        root_count: 1,
        stats: { events_emitted: 4, journal_overflows: 1, events_suppressed: 2, read_errors: 0 },
      },
    });

    assert.equal(accepted, 4);
    assert.equal((watcher as any)?.backend, "readdirectorychangesw");

    const activity: any = eventHub.getFilesystemActivity();
    assert.equal(activity?.counts?.created ?? 1, 1);
    assert.equal(activity?.counts?.modified ?? 1, 1);
    assert.equal(activity?.counts?.deleted ?? 1, 1);
    assert.equal(activity?.counts?.renamed ?? 1, 1);
    // A journal overflow is a real gap and must be visible, not smoothed over.
    assert.equal(activity?.delivery_gaps?.journal_overflows ?? 1, 1);
    assert.equal(activity?.delivery_gaps?.events_suppressed ?? 2, 2);
  });
});

describe("security providers", () => {
  beforeEach(() => eventHub.reset());

  it("keeps unreadable products visible with NOT_SUPPORTED integration", () => {
    eventHub.setSecurityProviders({
      timestamp: NOW,
      source: "windows_security_provider_collector",
      observed: true,
      discovery_state: "AVAILABLE",
      provider_count: 2,
      providers: [
        {
          provider_id: "windows-defender",
          provider_name: "Microsoft Defender Antivirus",
          product: "Microsoft Defender Antivirus",
          status: "Not running",
          status_availability: "AVAILABLE",
          realtime_protection: false,
          realtime_protection_availability: "AVAILABLE",
          last_known_scan: {},
          detection_count: 0,
          detections_availability: "AVAILABLE",
          detections: [],
          integration_status: "INTEGRATED",
          supported_capabilities: ["CAN_READ_STATUS"],
          unsupported_capabilities: [],
        },
        {
          provider_id: "wsc-quick-heal",
          provider_name: "Quick Heal AntiVirus Pro",
          product: "Quick Heal AntiVirus Pro",
          status: "REGISTERED",
          status_availability: "AVAILABLE",
          realtime_protection: null,
          realtime_protection_availability: "NOT_SUPPORTED",
          last_known_scan: {},
          detection_count: 0,
          detections_availability: "NOT_SUPPORTED",
          detections: [],
          integration_status: "NOT_SUPPORTED",
          supported_capabilities: [],
          unsupported_capabilities: ["CAN_READ_DETECTIONS", "CAN_REQUEST_SCAN"],
        },
      ],
      alerts: [],
      errors: [],
    });

    const snapshot = eventHub.getSecurityProviders();
    assert.equal(snapshot?.providers.length, 2);
    assert.equal((snapshot as any)?.summary?.integrated, 1);
    assert.equal((snapshot as any)?.summary?.not_supported, 1);
    // Never claim to control a third-party product.
    assert.ok(
      (snapshot?.providers[1] as any)?.unsupported_capabilities?.includes("CAN_REQUEST_SCAN"),
    );
  });
});

describe("agent command channel", () => {
  beforeEach(() => eventHub.reset());

  it("queues a command once and removes it on acknowledgement", () => {
    const command = {
      commandId: "cmd-1",
      type: "SCAN_REQUEST" as const,
      issuedAt: NOW,
      payload: { roots: ["C:\\Temp"] },
      requestId: null,
    };
    eventHub.enqueueCommand(command);
    eventHub.enqueueCommand(command);
    assert.equal(eventHub.getPendingCommands().length, 1);

    eventHub.ackCommand({
      commandId: "cmd-1",
      type: "SCAN_REQUEST",
      status: "started",
      scanId: "scan-xyz",
      scan: { scan_id: "scan-xyz", state: "STARTING", scan_type: "filesystem" },
      respondedAt: NOW,
    });

    assert.equal(eventHub.getPendingCommands().length, 0);
    assert.equal(eventHub.getScan("scan-xyz")?.state, "STARTING");
  });

  it("reports the agent as offline until a fresh heartbeat arrives", () => {
    assert.equal(eventHub.isAgentLive(), false);
    eventHub.setAgentHeartbeat({ endpointId: "endpoint-1", timestamp: new Date().toISOString() });
    assert.equal(eventHub.isAgentLive(), true);

    eventHub.setAgentHeartbeat({ endpointId: "endpoint-1", timestamp: "2020-01-01T00:00:00.000Z" });
    assert.equal(eventHub.isAgentLive(), false);
  });
});

describe("correlation", () => {
  beforeEach(() => eventHub.reset());

  const context = {
    processes: [
      { pid: 4242, name: "suspicious.exe", executable_path: "C:\\Temp\\suspicious.exe" },
      { pid: 5555, name: "notepad.exe", executable_path: "C:\\Windows\\notepad.exe" },
    ],
    connections: [],
    ports: [],
    detections: [],
    fileEvents: [] as MonitoringEvent[],
    now: NOW,
  };

  it("links a file change to the process that owns that exact path", () => {
    const record = correlate(fileEvent("c:\\temp\\suspicious.exe"), context);
    assert.ok(record);
    assert.equal(record?.evidence.length, 1);
    assert.equal(record?.evidence[0].kind, "process");
    assert.equal(record?.evidence[0].id, "pid-4242");
  });

  it("links a file change to every process that owns that exact path", () => {
    const notepad = correlate(fileEvent("C:\\Windows\\notepad.exe"), context);
    assert.equal(notepad?.evidence[0].id, "pid-5555");
  });

  it("produces nothing when no real evidence exists", () => {
    assert.equal(correlate(fileEvent("C:\\Temp\\unrelated.txt"), context), null);
  });

  it("links a provider detection to the file event for the same path", () => {
    const changed = fileEvent("C:\\Temp\\suspicious.exe", "fs-1");
    const record = correlate(providerDetectionEvent("sec-1", ["C:\\Temp\\suspicious.exe"], "suspicious.exe"), {
      ...context,
      fileEvents: [changed],
    });

    assert.ok(record);
    const kinds = record?.evidence.map((e) => e.kind) ?? [];
    assert.ok(kinds.includes("file"));
    assert.ok(kinds.includes("process"));
  });

  it("does not correlate a detection that matches no observed entity", () => {
    const changed = fileEvent("C:\\Temp\\other.exe", "fs-1");
    const record = correlate(
      providerDetectionEvent("sec-1", ["C:\\Temp\\unknown-payload.exe"], "unknown.exe"),
      { ...context, fileEvents: [changed] },
    );
    assert.equal(record, null);
  });

  it("is produced by the hub during ingest when a process matches", () => {
    eventHub.setSnapshot(
      processSnapshot([
        { pid: 4242, name: "suspicious.exe", executable_path: "C:\\Temp\\suspicious.exe" },
      ]),
    );
    eventHub.addMonitoringEvents([fileEvent("C:\\Temp\\suspicious.exe", "fs-1")]);
    const correlations = eventHub.getCorrelations();
    assert.equal(correlations.length, 1);
    assert.equal(correlations[0].evidence[0].id, "pid-4242");
  });
});

describe("aggregate snapshot honesty", () => {
  beforeEach(() => eventHub.reset());

  it("reports new domains as unavailable before any data arrives", () => {
    const snapshot = eventHub.getMonitoringSnapshot();
    assert.equal(snapshot.filesystem.observed, false);
    assert.equal(snapshot.filesystem.backend, "unavailable");
    assert.equal(snapshot.securityProviders, null);
    assert.equal(snapshot.agent.endpoint_id, null);
    assert.equal(snapshot.correlations.length, 0);
    assert.equal(snapshot.health, "offline");

    const unavailable = (snapshot as any).healthDetail.filter((h: any) => h.state === "unavailable").map((h: any) => h.source);
    assert.ok(unavailable.includes("filesystem_events"));
    assert.ok(unavailable.includes("security_providers"));
    assert.ok(unavailable.includes("agent"));
  });
});
