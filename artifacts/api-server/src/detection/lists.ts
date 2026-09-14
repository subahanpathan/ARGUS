/**
 * Static classification lists and path helpers used by the detection rules.
 * Names are matched case-insensitively with the `.exe` suffix ignored so that
 * rules keep working regardless of how a given telemetry source reports them.
 */

/** Script interpreters / command-line execution hosts. */
const SCRIPT_INTERPRETER_NAMES = new Set([
  "powershell",
  "powershell.exe",
  "powershell_ise",
  "powershell_ise.exe",
  "pwsh",
  "pwsh.exe",
  "cmd",
  "cmd.exe",
  "cscript",
  "cscript.exe",
  "wscript",
  "wscript.exe",
  "mshta",
  "mshta.exe",
  "regsvr32",
  "regsvr32.exe",
  "rundll32",
  "rundll32.exe",
  "wmic",
  "wmic.exe",
  "msiexec",
  "msiexec.exe",
  "conhost",
  "conhost.exe",
]);

/** Living-off-the-land binaries commonly abused by malware. */
const LOLBIN_NAMES = new Set([
  "certutil",
  "certutil.exe",
  "bitsadmin",
  "bitsadmin.exe",
  "regsvr32",
  "regsvr32.exe",
  "rundll32",
  "rundll32.exe",
  "mshta",
  "mshta.exe",
  "wmic",
  "wmic.exe",
  "forfiles",
  "forfiles.exe",
  "schtasks",
  "schtasks.exe",
  "net",
  "net.exe",
  "net1",
  "net1.exe",
  "taskkill",
  "taskkill.exe",
  "whoami",
  "whoami.exe",
  "cscript",
  "cscript.exe",
  "wscript",
  "wscript.exe",
]);

/** Product/user-interactive apps that should not normally spawn interpreters. */
const PRODUCTIVITY_APP_NAMES = new Set([
  "winword",
  "winword.exe",
  "excel",
  "excel.exe",
  "powerpnt",
  "powerpnt.exe",
  "outlook",
  "outlook.exe",
  "chrome",
  "chrome.exe",
  "msedge",
  "msedge.exe",
  "firefox",
  "firefox.exe",
  "thunderbird",
  "thunderbird.exe",
  "teams",
  "teams.exe",
  "iexplore",
  "iexplore.exe",
  "acrobat",
  "acrobat.exe",
  "acrord32",
  "acrord32.exe",
  "notepad",
  "notepad.exe",
  "eudora",
  "eudora.exe",
  "outlookexpress",
  "outlookexpress.exe",
]);

/** User-writable directory markers that make execution from them suspicious. */
const USER_WRITABLE_RE =
  /\\(temp|tmp|downloads?)\\|\\appdata\\|\\desktop\\|\\documents\\|\\onedrive\\|\\music\\|\\pictures\\|\\videos\\|\/tmp\/|\/home\/|\/var\/tmp\//i;

/** Script file extensions commonly used for dropped payloads. */
export const SCRIPT_EXTENSION_RE = /\.(ps1|psm1|vbs|vbe|js|jse|hta|bat|cmd|scr|jar|lnk)$/i;

export function normalizeProcessName(name: string | null | undefined): string {
  if (!name) return "";
  return name.trim().toLowerCase();
}

export function isScriptInterpreter(name: string | null | undefined): boolean {
  return SCRIPT_INTERPRETER_NAMES.has(normalizeProcessName(name));
}

export function isLolBin(name: string | null | undefined): boolean {
  return LOLBIN_NAMES.has(normalizeProcessName(name));
}

export function isProductivityApp(name: string | null | undefined): boolean {
  return PRODUCTIVITY_APP_NAMES.has(normalizeProcessName(name));
}

/**
 * True when the given text contains a user-writable directory marker
 * (Temp, Downloads, AppData, Desktop, Documents, OneDrive, ...).
 */
export function containsUserWritableDir(text: string | null | undefined): boolean {
  if (!text) return false;
  return USER_WRITABLE_RE.test(text);
}

/**
 * True when the given text is a path that lives inside a user-writable
 * directory. Falls back to `containsUserWritableDir` which is enough for
 * the values produced by the process monitor.
 */
export function isUserWritableExecutionPath(
  path: string | null | undefined,
): boolean {
  return containsUserWritableDir(path);
}

/** Extract a truncated command-line snippet for evidence (bounded length). */
export function snippet(text: string | null | undefined, max = 200): string | undefined {
  if (!text) return undefined;
  const cleaned = text.replace(/\s+/g, " ").trim();
  if (!cleaned) return undefined;
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned;
}