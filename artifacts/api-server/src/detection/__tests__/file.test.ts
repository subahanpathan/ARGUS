import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { FileScanSnapshot } from "../../lib/event-hub";
import type { FileViewEvent } from "../types";
import { normalizeFileFindings } from "../file/normalize";
import {
  evaluateFileRules,
  FILE_RULE_CATALOG,
  FILE_RULES,
} from "../file/rules";

function makeEvent(overrides: Partial<FileViewEvent> = {}): FileViewEvent {
  return {
    id: "file-1",
    type: "FILE_FINDING",
    origin: "snapshot",
    timestamp: "2026-01-01T12:00:00.000Z",
    source: "file_scanner",
    hostname: "win-host",
    pid: 4242,
    process_name: "evil.ps1",
    file_path: "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.ps1",
    file_name: "evil.ps1",
    file_extension: "ps1",
    file_hash: "a".repeat(64),
    file_size: 4096,
    category: "startup-file",
    className: "Persistence",
    is_running: true,
    finding_severity: "high",
    finding_reason: "executable in startup folder",
    executable_path: "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.ps1",
    metadata: { stableKey: "file:c:\\users\\alice\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\evil.ps1" },
    ...overrides,
  };
}

const FILE_001 = "FILE-001-STARTUP-PERSISTENCE";
const FILE_002 = "FILE-002-ENCODED-DOWNLOADER";
const FILE_003 = "FILE-003-CREDENTIAL-ACCESS-ARTIFACT";
const FILE_004 = "FILE-004-SCHEDULED-TASK-PERSISTENCE";
const FILE_005 = "FILE-005-DISGUISED-EXECUTABLE";
const FILE_006 = "FILE-006-RUNNING-SUSPECT";
const FILE_007 = "FILE-007-RECON-SCRIPT";

const matching = (event: FileViewEvent, ruleId: string) =>
  evaluateFileRules(event).find((m) => m.rule_id === ruleId);

describe("FILE_RULE_CATALOG", () => {
  it("exposes one entry per rule with unique ids", () => {
    assert.equal(FILE_RULE_CATALOG.length, FILE_RULES.length);
    const ids = new Set(FILE_RULE_CATALOG.map((r) => r.rule_id));
    assert.equal(ids.size, FILE_RULES.length);
  });
});

describe("normalizeFileFindings", () => {
  it("maps findings and resolves pid only for running artifacts", () => {
    const snapshot: FileScanSnapshot = {
      timestamp: "2026-01-01T12:00:00.000Z",
      total_count: 2,
      findings: [
        {
          id: "f-1",
          path: "C:\\Tools\\evil.ps1",
          name: "evil.ps1",
          extension: "ps1",
          hash: "b".repeat(64),
          size_bytes: 100,
          severity: "high",
          className: "Script",
          reason: "encoded",
          category: "encoded-powershell",
          is_running: true,
        },
        {
          id: "f-2",
          path: "C:\\Tools\\old.ps1",
          name: "old.ps1",
          severity: "low",
          className: "Script",
          reason: "none",
        },
      ],
    };
    const resolver = (path: string) => (path.includes("evil.ps1") ? 9001 : null);
    const [evil, old] = normalizeFileFindings(snapshot, resolver);

    assert.equal(evil.id, "file:f-1");
    assert.equal(evil.type, "FILE_FINDING");
    assert.equal(evil.pid, 9001);
    assert.equal(evil.is_running, true);
    assert.equal(evil.category, "encoded-powershell");

    assert.equal(old.pid, 0);
    assert.equal(old.is_running, false);
  });
});

describe("FILE-001 startup persistence", () => {
  it("flags a payload in a Startup folder at high severity", () => {
    const m = matching(makeEvent(), FILE_001);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.equal(m.baseConfidence, 0.7);
    assert.ok(m.evidence.some((e) => e.key === "startup_folder"));
  });

  it("elevates to critical when the payload carries credential/obfuscation markers", () => {
    const m = matching(
      makeEvent({ category: "startup-file / encoded-powershell" }),
      FILE_001,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "critical");
    assert.equal(m.baseConfidence, 0.8);
    assert.ok(m.evidence.some((e) => e.key === "payload_token"));
  });

  it("does not fire for non-startup categories", () => {
    assert.equal(matching(makeEvent({ category: "obfuscated-string" }), FILE_001), undefined);
  });
});

describe("FILE-002 encoded downloader", () => {
  it("flags an encoded-powershell script at high severity", () => {
    const m = matching(makeEvent({ category: "encoded-powershell" }), FILE_002);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
  });

  it("flags download-cradle primitives at high severity", () => {
    const m = matching(makeEvent({ category: "download-cradle" }), FILE_002);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
  });

  it("flags obfuscated content at medium severity", () => {
    const m = matching(makeEvent({ category: "obfuscated-string" }), FILE_002);
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
  });

  it("does not fire for unrelated categories", () => {
    assert.equal(matching(makeEvent({ category: "recon-commands" }), FILE_002), undefined);
  });
});

describe("FILE-003 credential access artifact", () => {
  it("flags lsass-access artifacts at critical severity", () => {
    const m = matching(makeEvent({ category: "lsass-access / mimikatz" }), FILE_003);
    assert.ok(m);
    assert.equal(m.baseSeverity, "critical");
    assert.equal(m.baseConfidence, 0.8);
    assert.ok(m.evidence.some((e) => e.key === "credential_token"));
  });

  it("does not fire for other categories", () => {
    assert.equal(matching(makeEvent({ category: "scheduled-task" }), FILE_003), undefined);
  });
});

describe("FILE-004 scheduled-task persistence", () => {
  it("flags scheduled-task scripts at medium severity", () => {
    const m = matching(makeEvent({ category: "scheduled-task" }), FILE_004);
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
  });
});

describe("FILE-005 disguised executable", () => {
  it("flags misleading filenames at medium severity", () => {
    const m = matching(makeEvent({ category: "misleading-name" }), FILE_005);
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
    assert.ok(m.evidence.some((e) => e.key === "misleading_name"));
  });
});

describe("FILE-006 running suspect", () => {
  it("elevates a medium-severity flagged artifact one severity step", () => {
    const m = matching(
      makeEvent({ category: "misleading-name", finding_severity: "medium" }),
      FILE_006,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.key === "running"));
  });

  it("defaults the base to medium when the scanner severity is unknown, then elevates to high", () => {
    const m = matching(
      makeEvent({ is_running: true, finding_severity: "info" }),
      FILE_006,
    );
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
  });

  it("does not fire for artifacts that are not running", () => {
    assert.equal(matching(makeEvent({ is_running: false }), FILE_006), undefined);
  });
});

describe("FILE-007 recon script", () => {
  it("flags recon-command scripts at low severity", () => {
    const m = matching(makeEvent({ category: "recon-commands" }), FILE_007);
    assert.ok(m);
    assert.equal(m.baseSeverity, "low");
    assert.ok(m.evidence.some((e) => e.key === "recon"));
  });
});

describe("evaluateFileRules combination", () => {
  it("does not throw for events with missing fields", () => {
    assert.deepEqual(evaluateFileRules(makeEvent({ category: undefined, is_running: false })), []);
  });

  it("evaluates cleanly for a finding that matches multiple rules", () => {
    const matches = evaluateFileRules(
      makeEvent({ category: "startup-file / misleading-name", finding_severity: "high" }),
    );
    const ids = matches.map((m) => m.rule_id);
    assert.ok(ids.includes(FILE_001));
    assert.ok(ids.includes(FILE_005));
    assert.ok(ids.includes(FILE_006));
  });
});