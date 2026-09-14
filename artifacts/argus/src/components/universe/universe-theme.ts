/**
 * universe-theme.ts — ARGUS Network Universe premium visual language.
 *
 * Centralized color system, process classification, deterministic hashing,
 * formatting helpers and cached canvas-based icon/glyph textures.
 *
 * All icons/textures are drawn locally onto canvas → THREE.CanvasTexture.
 * Real Windows executable icons are fetched (when available) from the
 * engine's /api/processes/icon endpoint and mixed in by the scene; this
 * module only renders the professional generic fallback.
 */

import * as THREE from "three";

/* ------------------------------------------------------------------ */
/* Color language                                                      */
/*                                                                    */
/*  CYAN/BLUE  → local endpoint, primary network, flow                */
/*  GREEN      → healthy / active telemetry state                     */
/*  AMBER      → attention / transitional state                        */
/*  PURPLE     → external / remote layer                               */
/*  RED        → genuine error/problem state only (rare)               */
/* ------------------------------------------------------------------ */

export const C = {
  bg: "#060a10",
  cyan: "#4fd6ff",
  cyanSoft: "#2a9db8",
  cyanDeep: "#1f7e9c",
  blue: "#5b8bd6",
  green: "#4fd6a3",
  greenMuted: "#2d8a6a",
  amber: "#e8a33d",
  amberDeep: "#8a6420",
  purple: "#a07be0",
  purpleDeep: "#5d47a8",
  purpleSoft: "#6f58c9",
  teal: "#3fd6c4",
  steel: "#5b8bd6",
  slate: "#7c93ab",
  muted: "#8da2b8",
  dim: "#24303d",
  white: "#eaf2fb",
  dark: "#0f1a26",
  panel: "#0c141e",
  panel2: "#0e1722",
  panelBorder: "#1c2c3c",
  cardEdge: "#223548",
  red: "#e5484d",
  danger: "#ff5f56",
  warn: "#e8a33d",
  ok: "#51d88a",
  soft: "#1c2938",
  gridLine: "#0c1622",
  gridSection: "#141f2e",
  floor: "#03070d",
};

/** Network/security state → color (controlled, no red for externals). */
export const SEC_COLOR: Record<string, string> = {
  normal: C.slate,
  active: C.cyan,
  suspicious: C.amber,
  threat: C.red,
  blocked: C.amberDeep,
  quarantined: C.teal,
  resolved: C.green,
};

/** Process family gallery → accent color used only for process identity. */
export const GAL: Record<string, string> = {
  browsing: C.cyan,
  terminal: C.green,
  office: C.amber,
  system: C.blue,
  dev: "#8fa6ff",
  media: "#e06c9f",
  cloud: C.purple,
  security: C.teal,
  generic: C.slate,
};

export const KIND: Record<string, string> = GAL;

/* ------------------------------------------------------------------ */
/* Process classification                                              */
/* ------------------------------------------------------------------ */

export function classifyProcess(name: string): { gallery: string; glyph: string } {
  const n = (name || "").toLowerCase();
  if (/(chrome|msedge|firefox|opera|brave|safari)/.test(n)) return { gallery: "browsing", glyph: "globe" };
  if (/(powershell|pwsh|cmd|conhost|windowsterminal|terminal|wt\.exe)/.test(n)) return { gallery: "terminal", glyph: "terminal" };
  if (/(code|codium|visualstudio|intellij|idea|webstorm|devenv|studio)/.test(n)) return { gallery: "dev", glyph: "code" };
  if (/(winword|word|excel|powerpnt|powerpoint|outlook|onenote|wps|office)/.test(n)) return { gallery: "office", glyph: "doc" };
  if (/explorer/.test(n)) return { gallery: "browsing", glyph: "folder" };
  if (/(svchost|services|lsass|csrss|wininit|winlogon|spoolsv|securityhealth|msmpeng|smss|taskschd)/.test(n)) return { gallery: "system", glyph: "shield" };
  if (/(onedrive|dropbox|slack|discord|teams|zoom|wechat|telegram)/.test(n)) return { gallery: "cloud", glyph: "cloud" };
  if (/(spotify|vlc|itunes|music|foobar|wmplayer)/.test(n)) return { gallery: "media", glyph: "music" };
  if (/(mysql|sqlserver|postgres|mongodb|redis|oracle|mariadb|sqlite)/.test(n)) return { gallery: "media", glyph: "db" };
  if (/(node|python|java|docker|git|rustc|gcc|go\.exe|pip)/.test(n)) return { gallery: "dev", glyph: "code" };
  if (/(notepad|wordpad|note)/.test(n)) return { gallery: "terminal", glyph: "edit" };
  if (/(search|startmenu|screensearch)/.test(n)) return { gallery: "system", glyph: "search" };
  if (/(server|sqlservr|nginx|apache|iis)/.test(n)) return { gallery: "dev", glyph: "server" };
  if (/(update|setup|installer|curl|wget|download)/.test(n)) return { gallery: "browsing", glyph: "download" };
  return { gallery: "generic", glyph: "grid" };
}

const procGlyphCache = new Map<string, string>();
export function getProcGlyph(name: string): string {
  let g = procGlyphCache.get(name);
  if (g) return g;
  g = classifyProcess(name).glyph;
  procGlyphCache.set(name, g);
  return g;
}

/* ------------------------------------------------------------------ */
/* Deterministic hashing                                               */
/* ------------------------------------------------------------------ */

export function h1(s: string): number {
  let x = 2166136261;
  for (let i = 0; i < s.length; i++) {
    x ^= s.charCodeAt(i);
    x = Math.imul(x, 16777619);
  }
  return x >>> 0;
}

export function hf(s: string): number {
  return h1(s) / 4294967295;
}

export function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, v));
}

/* ------------------------------------------------------------------ */
/* Formatting helpers                                                  */
/* ------------------------------------------------------------------ */

export function fmtRate(bytesPerSec: number): string {
  if (!bytesPerSec || bytesPerSec <= 0) return "0 B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let v = bytesPerSec;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function fmtBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

/* ------------------------------------------------------------------ */
/* Address helpers                                                     */
/* ------------------------------------------------------------------ */

export function isLocalAddr(addr: string): boolean {
  if (!addr) return false;
  return addr.startsWith("127.") || addr === "::1" || addr === "localhost";
}

export function isPublicRemote(addr: string): boolean {
  if (!addr) return false;
  if (addr.includes(":") && !addr.startsWith("192.168") && !addr.startsWith("10.") && !addr.startsWith("172.")) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) {
    const parts = addr.split(".").map(Number);
    return !(parts[0] === 10 || parts[0] === 127 || (parts[0] === 192 && parts[1] === 168) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31));
  }
  return true;
}

export function connKey(local: string | undefined, lp: number | undefined, remote: string | undefined, rp: number | undefined, proto: string | undefined): string {
  return `${local ?? ""}:${lp ?? 0}|${remote ?? ""}:${rp ?? 0}|${proto ?? ""}`;
}

/* ------------------------------------------------------------------ */
/* Canvas glyph rendering                                              */
/* ------------------------------------------------------------------ */

const glyphCanvasStore: Record<string, THREE.CanvasTexture> = {};

function drawGlyph(ctx: CanvasRenderingContext2D, kind: string, color: string, S: number): void {
  const stroke = (p: string, s: string, lw = 7) => {
    ctx.strokeStyle = s;
    ctx.lineWidth = lw;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.stroke(new Path2D(p));
  };
  const fill = (p: string, s: string) => {
    ctx.fillStyle = s;
    ctx.fill(new Path2D(p));
  };
  switch (kind) {
    case "globe":
      ctx.beginPath(); ctx.arc(S / 2, S / 2, 30, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      ctx.beginPath(); ctx.ellipse(S / 2, S / 2, 30, 13, 0, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 4; ctx.stroke();
      ctx.beginPath(); ctx.moveTo(S / 2, 34); ctx.lineTo(S / 2, 94); ctx.strokeStyle = color; ctx.lineWidth = 4; ctx.stroke();
      break;
    case "terminal": stroke("M44 48 L24 66 L44 84", color); stroke("M60 86 L96 86", color); break;
    case "code": stroke("M40 48 L20 66 L40 84", color); stroke("M88 48 L108 66 L88 84", color); stroke("M66 40 L62 90", color); break;
    case "doc":
      fill("M34 22 L74 22 L94 42 L94 106 L34 106 Z", "rgba(255,255,255,0.06)");
      stroke("M34 22 L74 22 L94 42 L94 106 L34 106 Z", color, 5);
      stroke("M74 22 L74 42 L94 42", color, 4);
      stroke("M46 66 L82 66", color, 5);
      stroke("M46 82 L82 82", color, 5);
      break;
    case "folder":
      fill("M18 34 L46 34 L56 48 L110 48 L110 96 L18 96 Z", "rgba(255,255,255,0.06)");
      stroke("M18 34 L46 34 L56 48 L110 48 L110 96 L18 96 Z", color, 5);
      break;
    case "cloud":
      ctx.beginPath(); ctx.arc(48, 68, 18, Math.PI * 0.6, Math.PI * 1.5); ctx.arc(72, 62, 24, Math.PI * 1.15, Math.PI * 0.5); ctx.arc(96, 70, 17, Math.PI * 0.9, Math.PI * 1.7);
      ctx.closePath(); ctx.fillStyle = "rgba(255,255,255,0.06)"; ctx.fill(); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      break;
    case "music":
      stroke("M78 32 L100 40", color);
      fill("M78 32 L96 24 L96 84 L78 84 L78 32 Z", "rgba(255,255,255,0.06)");
      ctx.beginPath(); ctx.arc(72, 84, 12, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      ctx.beginPath(); ctx.arc(98, 90, 12, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      break;
    case "db":
      ctx.beginPath(); ctx.ellipse(64, 42, 44, 16, 0, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      ctx.beginPath(); ctx.moveTo(20, 42); ctx.lineTo(20, 88); ctx.moveTo(108, 42); ctx.lineTo(108, 88); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      ctx.beginPath(); ctx.ellipse(64, 88, 44, 16, 0, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      break;
    case "shield":
      stroke("M64 20 L100 34 L96 72 C96 88 82 98 64 106 C46 98 32 88 32 72 L28 34 Z", color, 6);
      stroke("M64 96 L64 32", color, 5);
      stroke("M64 96 L86 88", color, 5);
      break;
    case "gear":
      ctx.beginPath(); ctx.arc(64, 64, 26, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 7; ctx.stroke();
      for (let i = 0; i < 8; i++) {
        const a = (i / 8) * Math.PI * 2;
        ctx.beginPath(); ctx.moveTo(64 + Math.cos(a) * 34, 64 + Math.sin(a) * 34); ctx.lineTo(64 + Math.cos(a) * 46, 64 + Math.sin(a) * 46); ctx.strokeStyle = color; ctx.lineWidth = 7; ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(64, 64, 11, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      break;
    case "search":
      ctx.beginPath(); ctx.arc(52, 54, 30, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 7; ctx.stroke();
      stroke("M76 78 L98 100", color, 8);
      break;
    case "edit": stroke("M30 92 L36 64 L84 20 L102 40 L54 90 Z", color, 6); stroke("M84 20 L102 40", color, 6); break;
    case "server":
      fill("M30 30 L98 30 L98 54 L30 54 Z", "rgba(255,255,255,0.06)");
      stroke("M30 30 L98 30 L98 54 L30 54 Z", color, 5);
      stroke("M30 70 L98 70 L98 94 L30 94 Z", color, 5);
      fill("M42 42 L50 42", color); fill("M42 82 L50 82", color);
      break;
    case "download":
      stroke("M64 18 L64 74", color, 7); stroke("M40 52 L64 76 L88 52", color, 7); stroke("M30 96 L98 96", color, 7);
      break;
    case "bud":
      ctx.beginPath(); ctx.arc(64, 64, 30, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      ctx.beginPath(); ctx.arc(64, 64, 10, 0, Math.PI * 2); ctx.strokeStyle = color; ctx.lineWidth = 6; ctx.stroke();
      break;
    default:
      stroke("M26 34 L102 34 M26 64 L102 64 M26 94 L102 94 M38 22 L38 106 M66 22 L66 106 M94 22 L94 106", "rgba(255,255,255,0.3)", 6);
      break;
  }
}

export function makeGlyphTexture(kind: string, color: string): THREE.CanvasTexture {
  const cacheKey = `${kind}-${color}`;
  const cached = glyphCanvasStore[cacheKey];
  if (cached) return cached;
  const S = 128;
  const c = document.createElement("canvas");
  c.width = S;
  c.height = S;
  const ctx = c.getContext("2d")!;
  ctx.clearRect(0, 0, S, S);
  ctx.translate(S, S);
  ctx.scale(-1, 1);
  ctx.translate(-S / 2, -S / 2);
  drawGlyph(ctx, kind, color, S);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 4;
  glyphCanvasStore[cacheKey] = t;
  return t;
}

/* ------------------------------------------------------------------ */
/* Professional generic executable icon                                */
/* ------------------------------------------------------------------ */

const execTextureCache = new Map<string, THREE.CanvasTexture>();

/**
 * Renders a professional generic executable/application tile (rounded,
 * gradient, window motif). Used when a real Windows icon is unavailable.
 * Never random — always the same disciplined shape, tinted by family color.
 */
export function makeExecIconTexture(name: string, color: string): THREE.CanvasTexture {
  const key = `${name}-${color}`;
  const cached = execTextureCache.get(key);
  if (cached) return cached;
  const S = 128;
  const c = document.createElement("canvas");
  c.width = S;
  c.height = S;
  const ctx = c.getContext("2d")!;

  const R = 26;
  const g = ctx.createLinearGradient(0, 0, S, S);
  g.addColorStop(0, "#1a2636");
  g.addColorStop(0.5, "#0d1520");
  g.addColorStop(1, "#080d15");
  rounded(ctx, 10, 10, S - 20, S - 20, R);
  ctx.fillStyle = g;
  ctx.fill();

  rounded(ctx, 10.5, 10.5, S - 21, S - 21, R);
  ctx.strokeStyle = "#2c3d54";
  ctx.lineWidth = 3;
  ctx.stroke();

  // accent keyline
  rounded(ctx, 14, 14, S - 28, 12, 6);
  ctx.fillStyle = color;
  ctx.globalAlpha = 0.9;
  ctx.fill();
  ctx.globalAlpha = 1;

  // window motif
  rounded(ctx, 26, 38, S - 52, S - 56, 8);
  ctx.fillStyle = "#0a1120";
  ctx.fill();
  ctx.strokeStyle = "#26374d";
  ctx.lineWidth = 2.5;
  ctx.stroke();

  ctx.fillStyle = "#16233a";
  rounded(ctx, 33, 45, S - 66, 9, 3);
  ctx.fill();
  ctx.fillStyle = "#1b2a44";
  rounded(ctx, 33, 61, S - 90, 5, 2);
  ctx.fill();
  rounded(ctx, 33, 73, S - 66, 5, 2);
  ctx.fill();
  rounded(ctx, 33, 85, S - 84, 5, 2);
  ctx.fill();

  ctx.fillStyle = color;
  ctx.globalAlpha = 0.85;
  rounded(ctx, 74, 90, 12, 6, 3);
  ctx.globalAlpha = 1;

  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 4;
  execTextureCache.set(key, t);
  return t;
}

function rounded(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.arcTo(x + w, y, x + w, y + rr, rr);
  ctx.lineTo(x + w, y + h - rr);
  ctx.arcTo(x + w, y + h, x + w - rr, y + h, rr);
  ctx.lineTo(x + rr, y + h);
  ctx.arcTo(x, y + h, x, y + h - rr, rr);
  ctx.lineTo(x, y + rr);
  ctx.arcTo(x, y, x + rr, y, rr);
  ctx.closePath();
}

/* ------------------------------------------------------------------ */
/* Real executable icon loading (backend /api/processes/icon)          */
/* ------------------------------------------------------------------ */

const realIconCache = new Map<string, string | null>();
const iconTextureByDataUrl = new Map<string, THREE.CanvasTexture<HTMLImageElement>>();

function makeTextureFromDataUrl(dataUrl: string): THREE.CanvasTexture<HTMLImageElement> {
  const cached = iconTextureByDataUrl.get(dataUrl);
  if (cached) return cached;
  const img = new Image();
  img.src = dataUrl;
  const t = new THREE.CanvasTexture(img);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 4;
  iconTextureByDataUrl.set(dataUrl, t);
  return t;
}

/** Preload the real executable icon (returns dataUrl or null on failure). */
export async function loadRealIcon(path: string, pid?: number): Promise<string | null> {
  const key = path || "";
  if (!key) return Promise.resolve(null);
  const cached = realIconCache.get(key);
  if (cached !== undefined) return Promise.resolve(cached);
  try {
    const suffix = pid ? `&pid=${pid}` : "";
    const resp = await fetch(`/api/processes/icon?${new URLSearchParams({ path })}${suffix}`);
    if (!resp.ok) {
      realIconCache.set(key, null);
      return null;
    }
    const blob = await resp.blob();
    const dataUrl = await new Promise<string | null>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : null);
      reader.onerror = () => resolve(null);
      reader.readAsDataURL(blob);
    });
    realIconCache.set(key, dataUrl);
    return dataUrl;
  } catch {
    realIconCache.set(key, null);
    return null;
  }
}

import { useState, useEffect } from "react";

/**
 * React hook returning a real executable-icon CanvasTexture when available.
 * Falls back to null (caller renders the generic professional icon).
 */
export function useRealIconTexture(iconPath?: string, pid?: number): THREE.CanvasTexture<HTMLImageElement> | null {
  const [dataUrl, setDataUrl] = useState<string | null>(() => {
    const key = iconPath || "";
    const cached = realIconCache.get(key);
    return cached !== undefined ? cached : null;
  });
  useEffect(() => {
    let alive = true;
    const key = iconPath || "";
    if (!key) return;
    const cached = realIconCache.get(key);
    if (cached !== undefined) {
      setDataUrl(cached);
      return;
    }
    loadRealIcon(key, pid).then((result) => {
      if (alive) setDataUrl(result);
    });
    return () => {
      alive = false;
    };
  }, [iconPath, pid]);
  if (!dataUrl) return null;
  return makeTextureFromDataUrl(dataUrl);
}