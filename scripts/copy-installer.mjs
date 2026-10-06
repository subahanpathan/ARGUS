/**
 * Copies the desktop installer into the frontend's public/ output so that
 * serverless hosts (Vercel) can serve /ARGUS-Setup.exe as a static asset.
 * The /api/desktop/download route redirects there when no installer is
 * bundled next to the function.
 *
 * Non-fatal: if the installer hasn't been built, the UI shows a friendly
 * "not available" message instead of a broken download.
 */
import { copyFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(root, "dist", "installer", "ARGUS-Setup.exe");
const destDir = path.join(root, "artifacts", "argus", "dist", "public");

if (existsSync(src)) {
  mkdirSync(destDir, { recursive: true });
  copyFileSync(src, path.join(destDir, "ARGUS-Setup.exe"));
  console.log(`[copy-installer] ARGUS-Setup.exe -> ${path.relative(root, path.join(destDir, "ARGUS-Setup.exe"))}`);
} else {
  console.warn("[copy-installer] dist/installer/ARGUS-Setup.exe not found - download endpoint will report unavailable until the desktop app is built.");
}
