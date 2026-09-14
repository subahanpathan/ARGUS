import { Router, type IRouter, type Request, type Response } from "express";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { logger } from "../lib/logger";

const execFileAsync = promisify(execFile);

const router: IRouter = Router();

/**
 * GET /api/processes/icon?path=C:\Windows\System32\notepad.exe
 * Returns the associated OS executable icon as PNG (read-only, no process
 * interaction). Used by the 3D universe process cards to render real icons.
 *
 * Safety: the icon extractor only reads the static icon resource embedded in
 * the file — it never launches, inspects payload, or reads file content, and
 * returns only a tiny rendered PNG bitmap.
 */

const iconCache = new Map<string, Buffer>();

function cacheSet(key: string, value: Buffer): void {
  if (iconCache.has(key)) {
    iconCache.set(key, value);
    return;
  }
  iconCache.set(key, value);
  // Bound the cache to prevent unbounded growth (simple FIFO eviction).
  if (iconCache.size > 256) {
    const oldest = iconCache.keys().next().value as string | undefined;
    if (oldest !== undefined) iconCache.delete(oldest);
  }
}

router.get("/processes/icon", async (req: Request, res: Response) => {
  const pathParam = typeof req.query.path === "string" ? req.query.path : "";

  // Accept only plausible absolute Windows file paths.
  if (!/^[A-Za-z]:[\\/]/.test(pathParam) || pathParam.length > 320) {
    res.status(400).json({ error: "Invalid path." });
    return;
  }

  const cached = iconCache.get(pathParam);
  if (cached) {
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.type("image/png");
    res.send(cached);
    return;
  }

  try {
    const base64 = await extractIconBase64(pathParam);
    const buffer = Buffer.from(base64, "base64");
    if (!base64 || buffer.length === 0) {
      res.status(404).json({ error: "No icon available." });
      return;
    }
    cacheSet(pathParam, buffer);
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.type("image/png");
    res.send(buffer);
  } catch (err) {
    logger.debug({ path: pathParam, err }, "icon extraction failed");
    res.status(404).json({ error: "No icon available." });
  }
});

async function extractIconBase64(filePath: string): Promise<string> {
  const script = [
    "Add-Type -AssemblyName System.Drawing",
    `$p = '${filePath.replace(/'/g, "''")}'`,
    "$i = [System.Drawing.Icon]::ExtractAssociatedIcon($p)",
    "if ($i) {",
    "  $b = $i.ToBitmap()",
    "  if ($b) {",
    "    $ms = New-Object System.IO.MemoryStream",
    "    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)",
    "    $result = [Convert]::ToBase64String($ms.ToArray())",
    "    $ms.Dispose()",
    "  }",
    "  $b.Dispose()",
    "  $i.Dispose()",
    "}",
    "if ($result) { $result } else { 'NOICON' }",
  ].join("; ");

  const encoded = Buffer.from(script, "utf16le").toString("base64");

  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
      { timeout: 8000, windowsHide: true, maxBuffer: 1_000_000, encoding: "utf8" },
    );
    const trimmed = (stdout ?? "").trim();
    return trimmed && trimmed !== "NOICON" ? trimmed : "";
  } catch {
    return "";
  }
}

export default router;