import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import {
  assertNotWorkspacePath,
  isAbsolutePath,
  isInsideRecoveryRoot,
  normalizePathKey,
  normalizeVolume,
  relativeToVolume,
  resolveInside,
  safeSegment,
  samePath,
  setRecoveryRoot,
  validateObservedPath,
  volumeOf,
} from "../paths";

describe("safeSegment", () => {
  it("collapses separators so a file name cannot become a directory", () => {
    const collapsed = safeSegment("..\\..\\windows\\system32\\cmd.exe");
    assert.ok(!collapsed.includes("/"));
    assert.ok(!collapsed.includes("\\"));
    assert.ok(!collapsed.startsWith("."));
    assert.equal(safeSegment("a/b/c.txt"), "a_b_c.txt");
  });

  it("removes drive colons and reserved characters", () => {
    assert.equal(safeSegment('C:"evil".txt'), "C__evil_.txt");
  });

  it("refuses to return a traversal segment", () => {
    assert.equal(safeSegment(".."), "_");
    assert.equal(safeSegment("."), "_");
    assert.equal(safeSegment(""), "unnamed");
    assert.equal(safeSegment("   "), "unnamed");
  });

  it("strips control characters and bounds the length", () => {
    assert.equal(safeSegment("re\u0000port.docx"), "report.docx");
    assert.equal(safeSegment("x".repeat(400)).length, 120);
  });

  it("keeps ordinary names recognisable", () => {
    assert.equal(safeSegment("Quarterly Report.docx"), "Quarterly Report.docx");
  });
});

describe("resolveInside", () => {
  const root = path.resolve("/tmp/argus-root");

  it("accepts nested paths inside the root", () => {
    const resolved = resolveInside(root, "staging/inc_1/rec_1/report.docx");
    assert.ok(resolved.startsWith(root), `${resolved} should be inside ${root}`);
    assert.ok(!resolved.includes(".."));
  });

  it("rejects traversal out of the root", () => {
    assert.throws(() => resolveInside(root, "../escape.txt"), /escapes the recovery root/);
    assert.throws(() => resolveInside(root, "staging/../../escape.txt"), /escapes the recovery root/);
  });

  it("rejects an absolute path outside the root", () => {
    assert.throws(() => resolveInside(root, "/etc/passwd"), /escapes the recovery root/);
  });

  it("rejects a sibling directory with a shared prefix", () => {
    assert.throws(() => resolveInside("/tmp/argus-root", "/tmp/argus-root-evil/x"), /escapes the recovery root/);
  });
});

describe("path canonicalisation", () => {
  it("case-folds and normalises separators", () => {
    assert.equal(normalizePathKey("C:\\Users\\A\\File.DOCX"), normalizePathKey("c:/users/a/file.docx"));
  });

  it("treats trailing separators as insignificant", () => {
    assert.ok(samePath("C:\\Users\\A\\", "c:\\users\\a"));
  });

  it("does not consider two empty paths equal", () => {
    assert.equal(samePath("", ""), false);
  });
});

describe("volume helpers", () => {
  it("extracts the windows volume without duplicating the colon", () => {
    assert.equal(volumeOf("C:\\Users\\a\\b.txt"), "c:");
    assert.equal(volumeOf("/home/a/b.txt"), null);
  });

  it("normalizes both `C:` and `C:\\` to the same canonical volume", () => {
    assert.equal(normalizeVolume("C:"), "c:");
    assert.equal(normalizeVolume("C:\\"), "c:");
    assert.equal(normalizeVolume("  D:  "), "d:");
    assert.equal(normalizeVolume("/home"), null);
  });

  it("returns a volume-relative path for shadow-copy lookups", () => {
    assert.equal(relativeToVolume("C:\\Users\\a\\b.txt"), "Users\\a\\b.txt");
    assert.equal(relativeToVolume("D:\\"), "");
    assert.equal(relativeToVolume("relative\\path"), null);
  });
});

describe("validateObservedPath", () => {
  it("accepts absolute paths", () => {
    assert.equal(validateObservedPath("C:\\Users\\a\\b.txt"), "C:\\Users\\a\\b.txt");
  });

  it("rejects relative paths, blanks, null bytes and non-strings", () => {
    assert.equal(validateObservedPath("Users\\a\\b.txt"), null);
    assert.equal(validateObservedPath(""), null);
    assert.equal(validateObservedPath("   "), null);
    assert.equal(validateObservedPath("C:\\a\u0000b"), null);
    assert.equal(validateObservedPath(42), null);
    assert.equal(validateObservedPath(undefined), null);
  });

  it("rejects absurdly long values", () => {
    assert.equal(validateObservedPath(`C:\\${"a".repeat(5000)}`), null);
  });
});

describe("workspace containment", () => {
  it("recognises paths inside the configured root", () => {
    setRecoveryRoot("/tmp/argus-workspace-test");
    try {
      assert.equal(isInsideRecoveryRoot("/tmp/argus-workspace-test/staging/a/b.docx"), true);
      assert.equal(isInsideRecoveryRoot("/tmp/argus-workspace-test"), true);
      assert.equal(isInsideRecoveryRoot("/tmp/elsewhere/b.docx"), false);
      assert.equal(throwsOnWorkspacePath("/tmp/argus-workspace-test/staging/a.docx"), true);
      assert.equal(throwsOnWorkspacePath("/tmp/elsewhere/b.docx"), false);
    } finally {
      setRecoveryRoot(null);
    }
  });
});

function throwsOnWorkspacePath(target: string): boolean {
  try {
    assertNotWorkspacePath(target, "refusing");
    return false;
  } catch {
    return true;
  }
}

describe("isAbsolutePath", () => {
  it("accepts a drive-qualified path and rejects a bare relative one", () => {
    assert.equal(isAbsolutePath("C:\\a\\b"), true);
    assert.equal(isAbsolutePath("a\\b"), false);
    assert.equal(isAbsolutePath(""), false);
  });
});
