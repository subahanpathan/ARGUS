/**
 * Static helpers for the FILE/PERSISTENCE detection domain.
 * File findings arrive pre-classified by the scanner (category tokens like
 * "startup-file", "encoded-powershell", "lsass-access", ...). The FILE rules
 * reason deterministically over those categories plus the real artifact
 * metadata (path, SHA-256 hash, size, mtime) and the running flag.
 */

/** Tokenize a scanner category string ("a / b / c") into trimmed tokens. */
export function categoryTokens(category: string | null | undefined): string[] {
  if (!category) return [];
  return category
    .split("/")
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length > 0);
}

/** True when the finding's category list contains the given token. */
export function hasCategoryToken(
  category: string | null | undefined,
  token: string,
): boolean {
  return categoryTokens(category).includes(token);
}

/** Tokens that make a persisted payload credential/obfuscation-capable. */
export const PAYLOAD_ESCALATION_TOKENS = new Set([
  "lsass-access",
  "encoded-powershell",
  "download-cradle",
]);

/** Recurring scanner categories surfaced by the FILE rule set. */
export const FILE_CATEGORIES = [
  "startup-file",
  "encoded-powershell",
  "download-cradle",
  "obfuscated-string",
  "lsass-access",
  "scheduled-task",
  "misleading-name",
  "recon-commands",
] as const;