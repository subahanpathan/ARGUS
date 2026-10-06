/**
 * monitoring-command-center-3d.tsx — ARGUS Monitoring Command Center 3D.
 *
 * Premium 3D visualization of the REAL monitored endpoint.
 *
 *   CENTER  : stylized 3D laptop/endpoint — the actual host being observed
 *   RING    : 8 monitoring domain modules (PROCESS, NETWORK, FILES, DISK,
 *             PORTS, SERVICES, SYSTEM, EVENTS)
 *   LINKS   : animated 3D data paths from the endpoint to each domain
 *
 * Every meaningful animation is driven by REAL backend telemetry:
 *   source liveness   → connection brightness + flow speed
 *   real metric value → domain module labels
 *   host health       → core ring color
 *
 * Ambient motion (particles, slow camera drift) is visibly distinct from
 * real activity. No fake numbers, no simulated traffic.
 */

import { useMemo, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, RoundedBox, Html, Grid, Line } from "@react-three/drei";
import * as THREE from "three";
import type {
  MonitoringSnapshot,
  MonitoringScanState,
} from "@/hooks/use-monitoring-stream";
import { C, clamp } from "../universe/universe-theme";

export type MonitoringDomainKey =
  | "process"
  | "network"
  | "files"
  | "disk"
  | "ports"
  | "services"
  | "system"
  | "events";

type Domain = {
  key: MonitoringDomainKey;
  label: string;
  color: string;
  angle: number;
  elevation: number;
  glyph: "stack" | "globe" | "folder" | "disk" | "ports" | "services" | "chip" | "stream";
};

const DOMAINS: Domain[] = [
  { key: "process", label: "PROCESS", color: C.cyan, angle: 0, elevation: 1.7, glyph: "stack" },
  { key: "network", label: "NETWORK", color: C.purple, angle: 45, elevation: 2.5, glyph: "globe" },
  { key: "files", label: "FILES", color: C.amber, angle: 90, elevation: 1.2, glyph: "folder" },
  { key: "disk", label: "DISK", color: C.teal, angle: 135, elevation: 2.2, glyph: "disk" },
  { key: "ports", label: "PORTS", color: C.blue, angle: 180, elevation: 1.6, glyph: "ports" },
  { key: "services", label: "SERVICES", color: C.steel, angle: 225, elevation: 0.8, glyph: "services" },
  { key: "system", label: "SYSTEM", color: C.greenMuted, angle: 270, elevation: 0.9, glyph: "chip" },
  { key: "events", label: "EVENTS", color: C.slate, angle: 315, elevation: 0.7, glyph: "stream" },
];

const RING_RADIUS = 5.9;

function domainPosition(d: Domain): [number, number, number] {
  const a = (d.angle * Math.PI) / 180;
  return [RING_RADIUS * Math.cos(a), d.elevation, RING_RADIUS * Math.sin(a)];
}

/* ------------------------------------------------------------------ */
/* Domain live-state resolver (pure — driven by real snapshot data)    */
/* ------------------------------------------------------------------ */

export type DomainState = {
  key: MonitoringDomainKey;
  live: boolean; // source currently reporting
  active: boolean; // has real observed metrics
  metric: string;
  metricLabel: string;
  pulse: number; // 0..1 animation intensity
};

export function resolveDomainStates(
  snapshot: MonitoringSnapshot | null,
  scan: MonitoringScanState | null,
  eventCount: number,
): DomainState[] {
  const srcState = (s: string) =>
    snapshot?.healthDetail.find((h) => h.source === s)?.state ?? "unavailable";
  const liveOf = (s: string) => srcState(s) === "live";

  const s = snapshot;
  const observed = (v: boolean) => (s ? v : false);
  const count = observed(true);

  const raw: Record<string, Omit<DomainState, "key" | "pulse">> = {
    process: {
      live: liveOf("process"),
      active: count && (s!.processes.total_count ?? 0) > 0,
      metric: s?.processes.observed ? String(s.processes.total_count ?? 0) : "—",
      metricLabel: s?.processes.observed ? "PIDs OBSERVED" : "UNAVAILABLE",
    },
    network: {
      live: liveOf("network"),
      active: count && (s!.network.total_count ?? 0) > 0,
      metric: s?.network.observed ? String(s.network.total_count ?? 0) : "—",
      metricLabel: s?.network.observed ? "CONNECTIONS" : "UNAVAILABLE",
    },
    files: {
      live: liveOf("files"),
      active: count && (scan?.files_scanned ?? 0) > 0,
      metric: scan ? String(scan.files_scanned ?? 0) : s?.files.observed ? String(s.files.findings ?? 0) : "—",
      metricLabel: scan ? "FILES SCANNED" : s?.files.observed ? "THREAT FINDINGS" : "NOT SCANNED",
    },
    disk: {
      live: liveOf("telemetry"),
      active: count && (s?.disks.length ?? 0) > 0,
      metric: s?.disks.length ? String(s.disks.length) : "—",
      metricLabel: s?.disks.length ? "VOLUMES MONITORED" : "UNAVAILABLE",
    },
    ports: {
      live: liveOf("ports"),
      active: count && ((s?.ports.tcp_listening ?? 0) + (s?.ports.udp_endpoints ?? 0)) > 0,
      metric: s?.ports.observed ? String((s.ports.tcp_listening ?? 0) + (s.ports.udp_endpoints ?? 0)) : "—",
      metricLabel: s?.ports.observed ? "LISTENING / UDP" : "UNAVAILABLE",
    },
    services: {
      live: liveOf("services"),
      active: count && (s?.services.total_count ?? 0) > 0,
      metric: s?.services.observed ? String(s.services.total_count ?? 0) : "—",
      metricLabel: s?.services.observed ? "SERVICES OBSERVED" : "UNAVAILABLE",
    },
    system: {
      live: liveOf("telemetry"),
      active: liveOf("telemetry"),
      metric: s?.endpoint.cpu_percent != null ? `${s.endpoint.cpu_percent.toFixed(1)}%` : "—",
      metricLabel: s?.endpoint.cpu_percent != null ? "CPU UTIL" : "UNAVAILABLE",
    },
    events: {
      live: liveOf("process") || liveOf("network"),
      active: eventCount > 0,
      metric: String(eventCount),
      metricLabel: "RECENT EVENTS",
    },
  };

  return DOMAINS.map((d) => {
    const st = raw[d.key];
    return {
      key: d.key,
      ...st,
      pulse: st.live ? 1 : snapshot ? 0.25 : 0,
    };
  });
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function dampn(a: number, b: number, lambda: number, dt: number): number {
  return b + (a - b) * Math.exp(-lambda * dt);
}

function buildCurve(from: [number, number, number], to: [number, number, number]) {
  const A = new THREE.Vector3(...from);
  const B = new THREE.Vector3(...to);
  const mid = A.clone().lerp(B, 0.5);
  const lift = clamp(A.distanceTo(B) * 0.22, 0.6, 1.7);
  const up = new THREE.Vector3(0, 1, 0);
  const c1 = A.clone().lerp(mid, 0.4).add(up.clone().multiplyScalar(lift * 0.35));
  const c2 = B.clone().lerp(mid, 0.4).add(up.clone().multiplyScalar(lift * 0.35));
  return new THREE.CatmullRomCurve3([A, c1, mid.clone().add(up.clone().multiplyScalar(lift)), c2, B]);
}

const _matCache = new Map<string, THREE.MeshStandardMaterial>();
function mat(color: string, emissive: string, emissiveIntensity: number, metalness = 0.2, roughness = 0.6): THREE.MeshStandardMaterial {
  const key = `${color}|${emissive}|${emissiveIntensity}|${metalness}|${roughness}`;
  const hit = _matCache.get(key);
  if (hit) return hit;
  const m = new THREE.MeshStandardMaterial({ color, emissive, emissiveIntensity, metalness, roughness });
  _matCache.set(key, m);
  return m;
}

/* ------------------------------------------------------------------ */
/* Core laptop                                                         */
/* ------------------------------------------------------------------ */

function LapTop({ snapshot, hostname }: { snapshot: MonitoringSnapshot | null; hostname: string }) {
  const health = snapshot?.health ?? "offline";
  const ringColor =
    health === "live" ? C.green : health === "partial" ? C.amber : health === "degraded" ? C.amberDeep : C.dim;
  const ring = useRef<THREE.Mesh>(null);
  const glow = useRef<THREE.Mesh>(null);

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime();
    if (ring.current) {
      ring.current.rotation.z += 0.004;
      const target = health === "live" ? 1.12 : health === "partial" ? 0.72 : 0.4;
      ring.current.scale.setScalar(dampn(ring.current.scale.x, target, 2.4, 0.016));
      (ring.current.material as THREE.MeshStandardMaterial).emissiveIntensity = clamp(0.5 + Math.sin(t * 2) * 0.25, 0.3, 1);
    }
    if (glow.current) {
      (glow.current.material as THREE.MeshBasicMaterial).opacity = clamp(0.38 + Math.sin(t * 1.4) * 0.12, 0.18, 0.55);
    }
  });

  return (
    <group position={[0, 0, 0]}>
      {/* observation ring */}
      <mesh ref={ring} rotation={[Math.PI / 2.4, 0, 0]} position={[0, 0.62, 0]}>
        <torusGeometry args={[2.4, 0.035, 12, 72]} />
        <meshStandardMaterial color={ringColor} emissive={ringColor} emissiveIntensity={0.9} transparent opacity={0.85} />
      </mesh>
      <mesh ref={glow} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.02, 0]}>
        <ringGeometry args={[1.7, 2.6, 48]} />
        <meshBasicMaterial color={ringColor} transparent opacity={0.22} side={THREE.DoubleSide} depthWrite={false} />
      </mesh>

      {/* laptop base */}
      <RoundedBox args={[4.4, 0.3, 3.1]} radius={0.14} smoothness={6} position={[0, 0.32, 0]} material={mat("#0d1826", "#0a141f", 0.25, 0.65, 0.35)} />
      {/* keyboard slab */}
      <RoundedBox args={[3.7, 0.08, 2.5]} radius={0.05} smoothness={4} position={[0, 0.5, 0]} material={mat("#111d2c", "#05090f", 0.2, 0.5, 0.7)} />

      {/* screen assembly */}
      <group position={[0, 0.62, -1.35]}>
        <RoundedBox args={[4.15, 2.9, 0.18]} radius={0.1} smoothness={5} position={[0, 1.55, 0]} rotation={[-0.18, 0, 0]} material={mat("#0d1826", "#0a141f", 0.25, 0.65, 0.35)} />
        <mesh position={[0, 1.55, 0.085]} rotation={[-0.18, 0, 0]}>
          <planeGeometry args={[3.75, 2.5]} />
          <meshBasicMaterial color="#06111d" />
        </mesh>
        <mesh position={[0, 1.55, 0.092]} rotation={[-0.18, 0, 0]}>
          <planeGeometry args={[3.2, 0.5]} />
          <meshBasicMaterial color="#0e2a3a" transparent opacity={0.9} />
        </mesh>
        <mesh position={[0, 1.82, 0.098]} rotation={[-0.18, 0, 0]}>
          <planeGeometry args={[2.2, 0.34]} />
          <meshBasicMaterial color="#123b52" transparent opacity={0.9} />
        </mesh>
        {/* status LED — real health color */}
        <mesh position={[1.72, 0.42, 0.03]}>
          <sphereGeometry args={[0.045, 12, 12]} />
          <meshBasicMaterial color={health === "live" ? C.green : health === "partial" ? C.amber : C.red} />
        </mesh>
      </group>

      {/* endpoint label */}
      <Html position={[0, -0.5, 0]} center zIndexRange={[30, 0]} style={{ pointerEvents: "none" }} wrapperClass="monitoring-ep-label">
        <div style={{ textAlign: "center", font: "600 10px var(--app-font-mono)", letterSpacing: ".12em", color: "#7fd8ff", textShadow: "0 0 12px rgba(80,180,255,.6)" }}>
          {hostname || "THIS HOST"}
          <div style={{ fontSize: 8, color: "#3d5a6e", letterSpacing: ".2em", marginTop: 2 }}>ARGUS MONITORING ENDPOINT</div>
        </div>
      </Html>
    </group>
  );
}

/* ------------------------------------------------------------------ */
/* Domain module glyphs                                                */
/* ------------------------------------------------------------------ */

function DomainGlyph({ domain, color, emissive, intensity, spinRef }: {
  domain: Domain;
  color: string;
  emissive: string;
  intensity: number;
  spinRef: { current: number };
}) {
  const matS = mat(color, emissive, intensity, 0.35, 0.5);
  const matE = mat("#02060b", emissive, Math.max(0.35, intensity), 0.1, 0.4);

  switch (domain.glyph) {
    case "stack": {
      const ref = useRef<THREE.Group>(null);
      useFrame(() => {
        if (ref.current) ref.current.rotation.y = spinRef.current * 0.5;
      });
      return (
        <group ref={ref}>
          <RoundedBox args={[0.95, 0.1, 0.7]} radius={0.04} smoothness={3} position={[-0.18, 0.12, 0]} material={matS} />
          <RoundedBox args={[0.85, 0.1, 0.62]} radius={0.04} smoothness={3} position={[0.14, 0.24, 0.05]} material={matE} />
          <RoundedBox args={[0.95, 0.1, 0.7]} radius={0.04} smoothness={3} position={[-0.06, 0.36, -0.05]} material={matS} />
          <RoundedBox args={[0.8, 0.1, 0.6]} radius={0.04} smoothness={3} position={[0.18, 0.48, 0.02]} material={matE} />
        </group>
      );
    }
    case "globe": {
      const ref = useRef<THREE.Group>(null);
      useFrame(() => {
        if (ref.current) ref.current.rotation.y = spinRef.current * 1.2;
      });
      return (
        <group ref={ref}>
          <mesh>
            <sphereGeometry args={[0.55, 24, 24]} />
            <meshStandardMaterial color={color} emissive={emissive} emissiveIntensity={intensity} wireframe transparent opacity={0.75} />
          </mesh>
          <mesh>
            <sphereGeometry args={[0.18, 16, 16]} />
            <meshStandardMaterial color={color} emissive={emissive} emissiveIntensity={intensity * 1.5} />
          </mesh>
        </group>
      );
    }
    case "folder": {
      return (
        <group>
          <RoundedBox args={[0.95, 0.12, 0.66]} radius={0.05} smoothness={3} position={[0, -0.1, 0]} material={matS} />
          <RoundedBox args={[0.78, 0.46, 0.52]} radius={0.05} smoothness={3} position={[0, 0.1, 0]} material={matE} />
          <mesh position={[0, 0.1, 0.265]}>
            <planeGeometry args={[0.3, 0.07]} />
            <meshBasicMaterial color={emissive} transparent opacity={0.5} />
          </mesh>
        </group>
      );
    }
    case "disk": {
      const ref = useRef<THREE.Group>(null);
      useFrame(() => {
        if (ref.current) ref.current.rotation.y = spinRef.current * 0.35;
      });
      return (
        <group ref={ref}>
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <cylinderGeometry args={[0.52, 0.52, 0.18, 32]} />
            <meshStandardMaterial color={color} emissive={emissive} emissiveIntensity={intensity} metalness={0.6} roughness={0.3} />
          </mesh>
          <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0, 0.1]}>
            <cylinderGeometry args={[0.52, 0.52, 0.05, 32]} />
            <meshStandardMaterial color="#0b1520" emissive={emissive} emissiveIntensity={intensity * 0.4} metalness={0.5} roughness={0.5} />
          </mesh>
          <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0, 0.095]}>
            <ringGeometry args={[0.12, 0.4, 28]} />
            <meshBasicMaterial color={emissive} transparent opacity={0.35} />
          </mesh>
        </group>
      );
    }
    case "ports": {
      return (
        <group>
          <RoundedBox args={[0.62, 0.88, 0.18]} radius={0.06} smoothness={3} material={matS} />
          {[0, 1, 2].map((i) => (
            <mesh key={`l${i}`} position={[-0.12, 0.26 - i * 0.24, 0.1]}>
              <boxGeometry args={[0.06, 0.1, 0.06]} />
              <meshBasicMaterial color={emissive} transparent opacity={0.8} />
            </mesh>
          ))}
          {[0, 1, 2].map((i) => (
            <mesh key={`r${i}`} position={[0.12, 0.26 - i * 0.24, 0.1]}>
              <boxGeometry args={[0.06, 0.1, 0.06]} />
              <meshStandardMaterial color={color} emissive={emissive} emissiveIntensity={intensity * 0.8} />
            </mesh>
          ))}
        </group>
      );
    }
    case "services": {
      return (
        <group>
          <RoundedBox args={[0.4, 0.56, 0.4]} radius={0.06} smoothness={3} material={matS} />
          <mesh position={[0, 0.14, 0.21]}>
            <boxGeometry args={[0.2, 0.05, 0.05]} />
            <meshBasicMaterial color={emissive} transparent opacity={0.7} />
          </mesh>
          <mesh position={[0, 0, 0.21]}>
            <boxGeometry args={[0.2, 0.05, 0.05]} />
            <meshBasicMaterial color={emissive} transparent opacity={0.5} />
          </mesh>
          <mesh position={[0, -0.14, 0.21]}>
            <boxGeometry args={[0.2, 0.05, 0.05]} />
            <meshBasicMaterial color={emissive} transparent opacity={0.5} />
          </mesh>
        </group>
      );
    }
    case "chip": {
      return (
        <group>
          <RoundedBox args={[0.62, 0.62, 0.12]} radius={0.05} smoothness={3} material={matS} />
          <RoundedBox args={[0.3, 0.3, 0.16]} radius={0.03} smoothness={2} material={matE} />
          {[0, 1, 2, 3].map((i) => (
            <mesh key={`p${i}`} position={[(i % 2 === 0 ? -1 : 1) * 0.26, (i < 2 ? 1 : -1) * 0.26, 0]}>
              <boxGeometry args={[0.05, 0.05, 0.12]} />
              <meshBasicMaterial color={emissive} transparent opacity={0.6} />
            </mesh>
          ))}
        </group>
      );
    }
    case "stream": {
      return (
        <group>
          <mesh rotation={[0, 0, Math.PI / 2]}>
            <torusGeometry args={[0.42, 0.035, 8, 40]} />
            <meshStandardMaterial color={color} emissive={emissive} emissiveIntensity={intensity} />
          </mesh>
          <mesh position={[0.42, 0, 0]} rotation={[0, 0, Math.PI / 2]}>
            <torusGeometry args={[0.16, 0.045, 8, 28]} />
            <meshStandardMaterial color={emissive} emissiveIntensity={intensity * 1.3} />
          </mesh>
        </group>
      );
    }
  }
}

/* ------------------------------------------------------------------ */
/* Domain modules                                                      */
/* ------------------------------------------------------------------ */

function DomainModule({ domain, ds }: { domain: Domain; ds: DomainState }) {
  const pos = domainPosition(domain);
  const group = useRef<THREE.Group>(null);
  const pulseRing = useRef<THREE.Mesh>(null);
  const spin = useRef(0);

  useFrame(({ clock }, delta) => {
    const t = clock.getElapsedTime();
    if (group.current) {
      group.current.position.y = dampn(group.current.position.y, pos[1] + Math.sin(t * 0.7 + domain.angle) * 0.12, 2.2, delta);
    }
    if (pulseRing.current) {
      const target = ds.live ? 1.18 + Math.sin(t * 2.2 + domain.angle) * 0.12 : 0.7;
      pulseRing.current.scale.setScalar(dampn(pulseRing.current.scale.x, target, 2.6, delta));
      (pulseRing.current.material as THREE.MeshBasicMaterial).opacity = ds.live ? clamp(0.5 + Math.sin(t * 2.6) * 0.18, 0.2, 0.8) : 0.15;
    }
    spin.current += delta * (ds.live ? 0.6 : 0.15);
  });

  const baseColor = ds.live ? domain.color : C.dim;
  const emissive = ds.live ? domain.color : "#0a1522";
  const intensity = ds.live ? (ds.active ? 1.1 : 0.55) : 0.12;

  return (
    <group ref={group} position={pos}>
      <Html position={[0, 1.35, 0]} center zIndexRange={[20, 0]} style={{ pointerEvents: "none" }} wrapperClass="monitoring-module-label">
        <div style={{ textAlign: "center", font: "700 9px var(--app-font-mono)", letterSpacing: ".16em", color: ds.live ? "#cde8ff" : "#5b7286", textShadow: ds.live ? `0 0 10px ${domain.color}66` : "none" }}>
          {domain.label}
          <div style={{ fontSize: 11, fontWeight: 800, color: ds.live ? "#eaf6ff" : "#40586c", marginTop: 2, letterSpacing: ".02em", fontFamily: "var(--app-font-mono)" }}>
            {ds.metric}
          </div>
          <div style={{ fontSize: 7, color: "#4a6a80", letterSpacing: ".12em", marginTop: 1 }}>{ds.metricLabel}</div>
        </div>
      </Html>

      {/* pulse ring */}
      <mesh ref={pulseRing} position={[0, 0, 0]} rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.82, 0.98, 40]} />
        <meshBasicMaterial color={baseColor} transparent opacity={0.4} side={THREE.DoubleSide} depthWrite={false} />
      </mesh>

      <DomainGlyph domain={domain} color={baseColor} emissive={emissive} intensity={intensity} spinRef={spin} />
    </group>
  );
}

/* ------------------------------------------------------------------ */
/* Healthy pulse status badge (DOM overlay)                            */
/* ------------------------------------------------------------------ */

function HealthStatus({ snapshot, scan, stale }: { snapshot: MonitoringSnapshot | null; scan: MonitoringScanState | null; stale: boolean }) {
  const health = snapshot?.health ?? "offline";
  const dots = snapshot?.healthDetail ?? [];
  const fmt = (v: string) => (v === "live" ? "LIVE" : v === "partial" ? "PARTIAL" : v === "degraded" ? "DEGRADED" : "OFFLINE");
  return (
    <div className="monitoring-health-banner" data-health={health}>
      <span className="monitoring-health-dot" data-health={health} />
      <span className="mono">{stale ? "STALE SIGNAL" : health === "live" ? "ALL SOURCES LIVE" : fmt(health)}</span>
      <span className="monitoring-health-sources">
        {dots.map((d) => (
          <span key={d.source} className="mono" data-source-state={d.state}>
            {d.source}:{fmt(d.state)}
          </span>
        ))}
        {scan && <span className="mono" data-source-state="live">scan:{scan.state}</span>}
      </span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Data links                                                          */
/* ------------------------------------------------------------------ */

function LinkLine({ points, color, ds }: { points: THREE.Vector3[]; color: string; ds: DomainState }) {
  const lineWrap = useRef<any>(null);

  useFrame((_, delta) => {
    const mat = lineWrap.current?.line?.material as { dashOffset: number; opacity: number } | undefined;
    if (!mat) return;
    const speed = ds.live ? 1.8 : ds.active ? 0.6 : 0.18;
    mat.dashOffset = (mat.dashOffset + speed * delta) % 1;
    mat.opacity = dampn(mat.opacity, ds.live ? 0.9 : 0.25, 2.4, delta);
  });

  return (
    <Line
      ref={lineWrap}
      points={points}
      color={color}
      lineWidth={1.25}
      dashed
      dashSize={0.42}
      gapSize={0.3}
      dashScale={2.2}
      transparent
      opacity={0.3}
      toneMapped={false}
      raycast={() => null}
    />
  );
}

function DomainLinks({ states }: { states: DomainState[] }) {
  return (
    <group>
      {states.map((ds) => {
        const domain = DOMAINS.find((d) => d.key === ds.key)!;
        const to = domainPosition(domain);
        const curve = useMemo(() => buildCurve([0, 0.62, 0], to), [to[0], to[1], to[2]]);
        const points = useMemo(() => curve.getPoints(28), [curve]);
        const color = ds.live ? domain.color : "#223544";
        return <LinkLine key={ds.key} points={points} color={color} ds={ds} />;
      })}
    </group>
  );
}

/* ------------------------------------------------------------------ */
/* Ambient particle field (static décor — not telemetry)               */
/* ------------------------------------------------------------------ */

function AmbientParticles() {
  const ref = useRef<THREE.Points>(null);
  const positions = useMemo(() => {
    const count = 380;
    const arr = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const r = 4 + Math.random() * 7;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      arr[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      arr[i * 3 + 1] = Math.abs(r * Math.cos(phi)) * 0.8 + 0.5;
      arr[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
    }
    return arr;
  }, []);

  useFrame(({ clock }) => {
    if (!ref.current) return;
    ref.current.rotation.y = clock.getElapsedTime() * 0.02;
    ref.current.rotation.x = Math.sin(clock.getElapsedTime() * 0.05) * 0.03;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.035} color="#3a5a72" transparent opacity={0.5} sizeAttenuation depthWrite={false} />
    </points>
  );
}

/* ------------------------------------------------------------------ */
/* Scene                                                                */
/* ------------------------------------------------------------------ */

function Scene({ snapshot, scan, eventCount, hostname }: { snapshot: MonitoringSnapshot | null; scan: MonitoringScanState | null; eventCount: number; hostname: string }) {
  const states = useMemo(() => resolveDomainStates(snapshot, scan, eventCount), [snapshot, scan, eventCount]);

  return (
    <>
      <color attach="background" args={["#04070d"]} />
      <fog attach="fog" args={["#04070d", 20, 40]} />

      <ambientLight intensity={0.4} />
      <pointLight position={[0, 7, 4]} intensity={60} color="#5fd6ff" distance={22} decay={2} />
      <pointLight position={[0, -2, -6]} intensity={30} color="#7e5fd6" distance={18} decay={2} />

      <Grid
        position={[0, -0.01, 0]}
        args={[60, 60]}
        cellSize={0.6}
        cellColor="#0c1a28"
        sectionSize={3}
        sectionColor="#12283c"
        fadeDistance={34}
        fadeStrength={1.6}
        infiniteGrid
      />

      <AmbientParticles />

      <LapTop snapshot={snapshot} hostname={hostname} />

      {DOMAINS.map((d) => {
        const ds = states.find((s) => s.key === d.key) ?? {
          key: d.key, live: false, active: false, metric: "—", metricLabel: "UNAVAILABLE", pulse: 0,
        };
        return <DomainModule key={d.key} domain={d} ds={ds} />;
      })}

      <DomainLinks states={states} />
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Public component                                                    */
/* ------------------------------------------------------------------ */

export function MonitoringCommandCenter3D({
  snapshot,
  scan,
  eventCount,
  hostname,
}: {
  snapshot: MonitoringSnapshot | null;
  scan: MonitoringScanState | null;
  eventCount: number;
  hostname: string;
}) {
  return (
    <div className="monitoring-3d-container" data-testid="monitoring-command-center-3d">
      <HealthStatus snapshot={snapshot} scan={scan} stale={false} />
      <Canvas
        camera={{ position: [6.5, 7, 13.5], fov: 44, near: 0.1, far: 90 }}
        dpr={[1, 1.6]}
        gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
        style={{ background: "transparent" }}
      >
        <Scene snapshot={snapshot} scan={scan} eventCount={eventCount} hostname={hostname} />
        <OrbitControls
          enablePan={false}
          minDistance={6}
          maxDistance={22}
          minPolarAngle={0.35}
          maxPolarAngle={Math.PI / 2.05}
          autoRotate
          autoRotateSpeed={0.45}
          enableDamping
          dampingFactor={0.08}
        />
      </Canvas>
    </div>
  );
}