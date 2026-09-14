import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { NetworkSnapshot, PortIntelligenceSnapshot } from "../../lib/event-hub";
import type { NetworkViewEvent } from "../types";
import {
  aggregateRemoteFanOut,
  normalizeNetworkConnections,
  normalizePortSnapshot,
} from "../network/normalize";
import {
  evaluateNetworkRules,
  NET_RULE_CATALOG,
  NET_RULES,
} from "../network/rules";

function makeEvent(overrides: Partial<NetworkViewEvent> = {}): NetworkViewEvent {
  return {
    id: "net-1",
    type: "NETWORK_CONNECTION",
    origin: "snapshot",
    timestamp: "2026-01-01T12:00:00.000Z",
    source: "windows_network_monitor",
    hostname: "win-host",
    pid: 4242,
    process_name: "svc.exe",
    executable_path: "C:\\Program Files\\Vendor\\svc.exe",
    protocol: "TCP",
    address_family: "IPv4",
    local_addr: "192.168.1.20",
    local_port: 50123,
    remote_addr: "8.8.8.8",
    remote_port: 443,
    local_role: "PRIVATE",
    remote_role: "REMOTE",
    state: "ESTABLISHED",
    metadata: {},
    ...overrides,
  };
}

const NET_001 = "NET-001-USER-WRITABLE-OUTBOUND";
const NET_002 = "NET-002-KNOWN-TOOL-PORT";
const NET_003 = "NET-003-SCRIPT-INTERPRETER-LISTENER";
const NET_004 = "NET-004-NEW-LISTENER-USER-WRITABLE";
const NET_005 = "NET-005-WILDCARD-LISTENER-USER-WRITABLE";
const NET_006 = "NET-006-INTERPRETER-REMOTE-CONNECTION";
const NET_007 = "NET-007-REMOTE-FAN-OUT";

const matching = (event: NetworkViewEvent, ruleId: string) =>
  evaluateNetworkRules(event).find((m) => m.rule_id === ruleId);

describe("NET_RULE_CATALOG", () => {
  it("exposes one entry per rule with unique ids", () => {
    assert.equal(NET_RULE_CATALOG.length, NET_RULES.length);
    const ids = new Set(NET_RULE_CATALOG.map((r) => r.rule_id));
    assert.equal(ids.size, NET_RULES.length);
  });
});

describe("normalizeNetworkConnections", () => {
  it("maps connections to view events with stable ids and roles", () => {
    const snapshot: NetworkSnapshot = {
      timestamp: "2026-01-01T12:00:00.000Z",
      total_count: 2,
      established_count: 2,
      listen_count: 0,
      connections: [
        {
          process: "svc.exe",
          pid: 4242,
          connection_id: "conn-1",
          type: "SOCK_STREAM",
          local_addr: "192.168.1.20",
          local_port: 50123,
          remote_addr: "8.8.8.8",
          remote_port: 443,
          status: "ESTABLISHED",
          local_role: "PRIVATE",
          remote_role: "REMOTE",
        },
        {
          process: "System",
          pid: 4,
          connection_id: "conn-2",
          type: "SOCK_STREAM",
          local_addr: "0.0.0.0",
          local_port: 445,
          status: "LISTEN",
          local_role: "WILDCARD",
          remote_role: "UNKNOWN",
        },
      ],
    };
    const [a, b] = normalizeNetworkConnections(snapshot);
    assert.equal(a.id, "net:conn-1");
    assert.equal(a.type, "NETWORK_CONNECTION");
    assert.equal(a.protocol, "TCP");
    assert.equal(a.remote_role, "REMOTE");
    assert.equal(a.state, "ESTABLISHED");
    assert.equal(a.pid, 4242);
    assert.equal((a.metadata?.stableKey as string), "net:conn-1");

    assert.equal(b.pid, 4);
    assert.equal(b.state, "LISTEN");
  });

  it("falls back to pid 0 when the socket owner is unknown", () => {
    const [evt] = normalizeNetworkConnections({
      timestamp: "2026-01-01T12:00:00.000Z",
      total_count: 1,
      established_count: 1,
      listen_count: 0,
      connections: [{ process: "System", pid: 0, type: "SOCK_DGRAM" }],
    });
    assert.equal(evt.pid, 0);
    assert.equal(evt.process_name, "System");
    assert.equal(evt.protocol, "UDP");
  });
});

describe("normalizePortSnapshot", () => {
  it("emits listener, endpoint and PORT_OPENED events with port ids", () => {
    const snapshot: PortIntelligenceSnapshot = {
      timestamp: "2026-01-01T12:00:00.000Z",
      tcp_listening: [
        {
          port_id: "pt-1",
          protocol: "TCP",
          local_addr: "0.0.0.0",
          local_port: 6666,
          pid: 4242,
          process_name: "bot.exe",
          binding_type: "WILDCARD",
          state: "LISTENING",
        },
      ],
      udp_endpoints: [{ port_id: "pt-2", protocol: "UDP", pid: 0 }],
      port_events: [
        {
          event_type: "PORT_OPENED",
          port_id: "pt-3",
          local_port: 31337,
          pid: 9001,
          process_name: "evil.exe",
          executable_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe",
          binding_type: "WILDCARD",
        },
      ],
    };
    const events = normalizePortSnapshot(snapshot);
    assert.equal(events.length, 3);
    const listener = events.find((e) => e.port_id === "pt-1")!;
    assert.equal(listener.type, "NETWORK_PORT");
    assert.equal(listener.local_port, 6666);
    assert.equal(listener.binding_type, "WILDCARD");
    const opened = events.find((e) => e.port_id === "pt-3")!;
    assert.equal(opened.event_type, "PORT_OPENED");
    assert.equal(opened.pid, 9001);
  });
});

describe("aggregateRemoteFanOut", () => {
  it("groups per-pid distinct REMOTE destinations", () => {
    const snapshot: NetworkSnapshot = {
      timestamp: "2026-01-01T12:00:00.000Z",
      total_count: 5,
      established_count: 4,
      listen_count: 1,
      connections: [
        { process: "srv", pid: 10, remote_addr: "1.1.1.1", remote_role: "REMOTE" },
        { process: "srv", pid: 10, remote_addr: "2.2.2.2", remote_role: "REMOTE" },
        { process: "srv", pid: 10, remote_addr: "1.1.1.1", remote_role: "REMOTE" },
        { process: "srv", pid: 10, remote_addr: "10.0.0.5", remote_role: "PRIVATE" },
        { process: "local", pid: 0, remote_addr: "9.9.9.9", remote_role: "REMOTE" },
      ],
    };
    const out = aggregateRemoteFanOut(snapshot);
    assert.equal(out.length, 1);
    assert.equal(out[0].pid, 10);
    assert.equal(out[0].count, 2);
    assert.deepEqual(out[0].remote_ips.slice().sort(), ["1.1.1.1", "2.2.2.2"]);
  });
});

describe("NET-001 user-writable outbound", () => {
  it("flags a user-writable binary with an established public connection", () => {
    const m = matching(
      makeEvent({
        executable_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\beacon.exe",
      }),
      NET_001,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.source === "path"));
    assert.ok(m.evidence.some((e) => e.source === "network"));
  });

  it("does not fire for a system32 binary or non-ESTABLISHED state", () => {
    assert.equal(
      matching(
        makeEvent({ executable_path: "C:\\Windows\\System32\\svchost.exe" }),
        NET_001,
      ),
      undefined,
    );
    assert.equal(
      matching(makeEvent({ state: "LISTEN" }), NET_001),
      undefined,
    );
  });
});

describe("NET-002 known tool port", () => {
  it("flags an established connection to an offensive-tooling port", () => {
    const m = matching(makeEvent({ remote_port: 4444 }), NET_002);
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
    assert.ok(m.evidence.some((e) => e.key === "known_tool_port"));
  });

  it("does not fire for non-tooling ports or non-remote endpoints", () => {
    assert.equal(matching(makeEvent({ remote_port: 443 }), NET_002), undefined);
    assert.equal(
      matching(makeEvent({ remote_port: 4444, remote_role: "PRIVATE" }), NET_002),
      undefined,
    );
  });
});

describe("NET-003 script interpreter listener", () => {
  it("flags an interpreter listening on a wildcard address", () => {
    const m = matching(
      makeEvent({
        type: "NETWORK_PORT",
        process_name: "powershell.exe",
        local_addr: "0.0.0.0",
        local_port: 4445,
        state: "LISTENING",
        binding_type: "WILDCARD",
      }),
      NET_003,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
  });

  it("does not fire for loopback listeners or non-interpreters", () => {
    assert.equal(
      matching(
        makeEvent({
          type: "NETWORK_PORT",
          process_name: "powershell.exe",
          local_addr: "127.0.0.1",
          local_port: 4445,
          state: "LISTENING",
          binding_type: "LOOPBACK",
        }),
        NET_003,
      ),
      undefined,
    );
    assert.equal(
      matching(
        makeEvent({
          type: "NETWORK_PORT",
          process_name: "svchost.exe",
          local_addr: "0.0.0.0",
          state: "LISTENING",
        }),
        NET_003,
      ),
      undefined,
    );
  });
});

describe("NET-004 new listener user-writable", () => {
  it("flags a PORT_OPENED event from a user-writable binary", () => {
    const m = matching(
      makeEvent({
        type: "NETWORK_PORT",
        event_type: "PORT_OPENED",
        local_port: 31337,
        local_addr: "0.0.0.0",
        binding_type: "WILDCARD",
        executable_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe",
      }),
      NET_004,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.source === "port"));
  });

  it("does not fire for a system32 binary open event", () => {
    assert.equal(
      matching(
        makeEvent({
          type: "NETWORK_PORT",
          event_type: "PORT_OPENED",
          executable_path: "C:\\Windows\\System32\\svchost.exe",
        }),
        NET_004,
      ),
      undefined,
    );
    assert.equal(
      matching(makeEvent({ type: "NETWORK_PORT", event_type: "PORT_CLOSED" }), NET_004),
      undefined,
    );
  });
});

describe("NET-005 wildcard listener user-writable", () => {
  it("flags an existing wildcard listener owned by a user-writable binary", () => {
    const m = matching(
      makeEvent({
        type: "NETWORK_PORT",
        state: "LISTENING",
        local_addr: "0.0.0.0",
        local_port: 9999,
        binding_type: "WILDCARD",
        executable_path: "C:\\Users\\alice\\Downloads\\server.exe",
      }),
      NET_005,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
  });
});

describe("NET-006 interpreter remote connection", () => {
  it("flags a script interpreter holding an established public connection", () => {
    const m = matching(
      makeEvent({
        process_name: "powershell.exe",
        executable_path:
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      }),
      NET_006,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
  });

  it("does not fire for a non-interpreter with a public connection", () => {
    assert.equal(
      matching(makeEvent({ process_name: "firefox.exe" }), NET_006),
      undefined,
    );
  });
});

describe("NET-007 remote fan-out", () => {
  it("flags a synthetic event with 10+ distinct remote destinations", () => {
    const m = matching(
      makeEvent({
        metadata: {
          stableKey: "fan:4242",
          fanOut: 12,
          remoteIps: Array.from({ length: 12 }, (_, i) => `10.${i}.1.1`),
        },
      }),
      NET_007,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "low");
    assert.ok(m.evidence.some((e) => e.key === "fan_out"));
  });

  it("does not fire below the threshold", () => {
    assert.equal(
      matching(makeEvent({ metadata: { fanOut: 3 } }), NET_007),
      undefined,
    );
  });
});

describe("evaluateNetworkRules combination", () => {
  it("does not throw for missing fields and produces no matches for clean traffic", () => {
    assert.deepEqual(
      evaluateNetworkRules({
        id: "net-clean-1",
        type: "NETWORK_CONNECTION",
        origin: "snapshot",
        timestamp: "2026-01-01T12:00:00.000Z",
        source: "windows_network_monitor",
        hostname: "win-host",
        pid: 100,
        process_name: "chrome.exe",
        remote_role: "PRIVATE",
        state: "ESTABLISHED",
        metadata: {},
      }),
      [],
    );
  });
});