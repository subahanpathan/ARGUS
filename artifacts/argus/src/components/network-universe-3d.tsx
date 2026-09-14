/**
 * network-universe-3d.tsx — ARGUS Network Universe, premium 3D scene.
 *
 * Phase 6  — redesigned 3D network environment (hierarchy, entity
 *            language, spatial composition, camera, labels, depth,
 *            cinematic interaction).
 * Phase 7  — event-driven real-time animation driven by the SSE stream
 *            (process/port/connection lifecycle, flow, spawn/despawn).
 *
 * Every meaningful entity and every animated relationship comes from real
 * ARGUS telemetry (built by universe-model.ts). Ambient motion is purely
 * visual — it never fabricates network traffic.
 */

import {
  useRef,
  useMemo,
  useCallback,
  useEffect,
  useState,
  createContext,
  useContext,
} from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls, Text, RoundedBox, Billboard, Html, Grid } from "@react-three/drei";
import * as THREE from "three";
import type {
  NetworkTopologyData,
  TopologyConnectionEvent,
  UniverseNode,
  UniverseLink,
  UniverseModel,
  UniverseStats,
  PortIntelligenceData,
  PortEvent,
  SecurityState,
} from "./network-universe-types";
import {
  C,
  SEC_COLOR,
  GAL,
  classifyProcess,
  getProcGlyph,
  h1,
  hf,
  clamp,
  fmtRate,
  connKey,
  makeGlyphTexture,
  makeExecIconTexture,
  useRealIconTexture,
} from "./universe/universe-theme";
import {
  buildUniverseModel,
  defaultStats,
  nodeRadius,
  nodeTint,
} from "./universe/universe-model";
import type { NetworkMode } from "@/hooks/use-simulated-network";

export type CameraMode = "3d" | "2d" | "top";

/* ================================================================== */
/* Quality level                                                       */
/* ================================================================== */

type QualityLevel = "high" | "medium" | "low";

/* ================================================================== */
/* Collision-free camera-friendly helpers                              */
/* ================================================================== */

const _v1 = new THREE.Vector3();
const _v2 = new THREE.Vector3();

function dampn(a: number, b: number, lambda: number, dt: number): number {
  return b + (a - b) * Math.exp(-lambda * dt);
}

function dampAngle(a: number, b: number, lambda: number, dt: number): number {
  let d = b - a;
  d = Math.atan2(Math.sin(d), Math.cos(d));
  return a + d * (1 - Math.exp(-lambda * dt));
}

/* ================================================================== */
/* Curve + link animation                                              */
/* ================================================================== */

function buildCurve(a: [number, number, number], b: [number, number, number], arch: number) {
  const A = new THREE.Vector3(a[0], a[1], a[2]);
  const B = new THREE.Vector3(b[0], b[1], b[2]);
  const mid = _v1.copy(A).lerp(B, 0.5);
  const dist = A.distanceTo(B);
  const lift = clamp(dist * 0.32, 0.55, arch);
  const c1 = _v2
    .copy(A)
    .lerp(mid, 0.4)
    .add(new THREE.Vector3(0, 1, 0).multiplyScalar(lift * 0.3));
  const c2 = new THREE.Vector3()
    .copy(B)
    .lerp(mid, 0.4)
    .add(new THREE.Vector3(0, 1, 0).multiplyScalar(lift * 0.3));
  const curve = new THREE.CatmullRomCurve3([
    A,
    c1,
    mid.clone().add(new THREE.Vector3(0, 1, 0).multiplyScalar(lift)),
    c2,
    B,
  ]);
  const points = curve.getPoints(24);
  points.forEach((p) => {
    p.y += 0.035;
  });
  return { curve, points };
}

function pointAt(points: THREE.Vector3[], t: number, dst: THREE.Vector3): THREE.Vector3 {
  const n = points.length - 1;
  const ft = clamp(t, 0, 1) * n;
  const i = Math.min(n - 1, Math.floor(ft));
  const f = ft - i;
  return dst.lerpVectors(points[i], points[i + 1], f);
}

type LinkAnim = {
  id: string;
  link: UniverseLink;
  from: [number, number, number];
  to: [number, number, number];
  points: THREE.Vector3[];
  phase: "form" | "flow" | "idle" | "close";
  phaseT: number;
  burst: number;
  alpha: number;
  dying: boolean;
  curve: THREE.CatmullRomCurve3 | null;
  geometry: THREE.TubeGeometry | null;
};

function makeLinkAnim(link: UniverseLink, from: [number, number, number], to: [number, number, number]): LinkAnim {
  const arch = link.edge === "remote" ? 5.2 : link.edge === "infra" ? 3.4 : 2.0;
  const { curve, points } = buildCurve(from, to, arch);
  return {
    id: link.id,
    link,
    from,
    to,
    points,
    phase: link.state === "flowing" ? "form" : "idle",
    phaseT: 0,
    burst: 0,
    alpha: 0,
    dying: false,
    curve,
    geometry: curve ? new THREE.TubeGeometry(curve, 24, 0.007, 6, false) : null,
  };
}

function linkColorFor(link: UniverseLink, selected: boolean): string {
  if (selected) return C.white;
  const s = link.secState;
  if (s === "threat") return C.red;
  if (s === "blocked") return C.red;
  if (s === "suspicious") return C.amber;
  if (s === "quarantined") return C.teal;
  if (link.edge === "remote") return C.purpleSoft;
  if (link.edge === "port") return C.cyan;
  if (link.edge === "lan") return C.cyanDeep;
  if (link.edge === "infra") return C.blue;
  if (link.protocol === "UDP" || link.protocol === "UDP6") return C.purple;
  if (link.edge === "proc") return C.cyanDeep;
  return C.dim;
}

function computedTargetAlpha(anim: LinkAnim, dim: number, selected: boolean): number {
  if (anim.dying) return 0;
  if (selected) return 0.92;
  if (dim < 0.5) return 0.12;
  if (anim.phase === "form") return 0.75;
  if (anim.phase === "close") return 0.08;
  if (anim.link.state === "flowing") return 0.42 + Math.min(0.26, anim.burst);
  if (anim.link.state === "active") return 0.28;
  if (anim.link.secState === "suspicious") return 0.3;
  if (anim.link.secState === "blocked") return 0.34;
  return 0.09;
}

function packetAmountFor(link: UniverseLink, flowBoost: number): number {
  const s = link.secState;
  if (s === "threat" || s === "blocked") return 0;
  if (link.state === "flowing") return Math.round(2 + flowBoost * 2.4);
  if (link.state === "active" || s === "active") return 1 + (flowBoost > 1.1 ? 1 : 0);
  if (s === "suspicious") return 1;
  return 0;
}

/* ================================================================== */
/* Shared scene context                                                */
/* ================================================================== */

type PacketBind = {
  key: string;
  points: THREE.Vector3[];
  amount: number;
  speed: number;
  dir: 1 | -1;
  color: THREE.Color;
  offsets: number[];
};

type SceneShared = {
  paused: boolean;
  reducedMotion: boolean;
  qualityRef: { current: QualityLevel };
  linkStore: { current: Map<string, LinkAnim> };
  packetStore: { current: Map<string, PacketBind> };
  dblFocus: { current: string | null };
  hoverId: string | null;
  setHoverId: (id: string | null) => void;
  pulseMap: { current: Map<string, number> };
};

const fallbackShared: SceneShared = {
  paused: false,
  reducedMotion: false,
  qualityRef: { current: "high" },
  linkStore: { current: new Map() },
  packetStore: { current: new Map() },
  dblFocus: { current: null },
  hoverId: null,
  setHoverId: () => {},
  pulseMap: { current: new Map() },
};

const SceneSharedCtx = createContext<SceneShared>(fallbackShared);
function useSceneShared() {
  return useContext(SceneSharedCtx);
}

/* ================================================================== */
/* Pulse driver — ages event-pulse rings and removes them when done    */
/* ================================================================== */

function EventPulseDriver() {
  const shared = useSceneShared();
  useFrame((_, delta) => {
    const m = shared.pulseMap.current;
    if (!m.size) return;
    const dt = Math.min(delta, 0.05);
    for (const [k, v] of [...m]) {
      const nv = v + dt;
      if (nv > 2.6) m.delete(k);
      else m.set(k, nv);
    }
  });
  return null;
}

function ping(id: string, pulseMap: { current: Map<string, number> }) {
  pulseMap.current.set(id, 0);
}

/* ================================================================== */
/* Shared geometries                                                   */
/* ================================================================== */

const sharedGeo = new Map<string, THREE.BufferGeometry>();
function geo(key: string, make: () => THREE.BufferGeometry): THREE.BufferGeometry {
  let g = sharedGeo.get(key);
  if (!g) {
    g = make();
    sharedGeo.set(key, g);
  }
  return g;
}
const sharedCone = geo("cone", () => new THREE.ConeGeometry(1, 1, 5));
const sharedOcta = geo("octa", () => new THREE.OctahedronGeometry(1, 0));
const sharedHex = geo("hex", () => new THREE.CylinderGeometry(1, 1, 1, 6));

/* ================================================================== */
/* Pointer helper                                                      */
/* ================================================================== */

function NodePointer({ size, onClick, onHover, onDoubleClick }: {
  size: number;
  onClick: () => void;
  onHover: (h: boolean) => void;
  onDoubleClick?: () => void;
}) {
  return (
    <mesh
      onPointerOver={(e) => {
        e.stopPropagation();
        onHover(true);
      }}
      onPointerOut={() => onHover(false)}
      onPointerDown={(e) => e.stopPropagation()}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      onDoubleClick={(e) => {
        e.stopPropagation();
        onDoubleClick?.();
      }}
    >
      <sphereGeometry args={[size, 10, 10]} />
      <meshBasicMaterial transparent opacity={0} depthWrite={false} />
    </mesh>
  );
}

function CycleOpacity({ ref, base, active, dim, speed }: {
  ref: React.RefObject<THREE.Mesh | null>;
  base: number;
  active: boolean;
  dim: number;
  speed: number;
}) {
  const shared = useSceneShared();
  useFrame((state) => {
    const r = ref.current;
    if (!r) return;
    const m = (r as THREE.Mesh).material as THREE.MeshBasicMaterial;
    m.opacity = (active ? base + Math.sin(state.clock.elapsedTime * speed) * base * 0.35 : base * 0.4) * dim;
  });
  void shared;
  return null;
}

/* ================================================================== */
/* STATE DECORATION — restrained, no red for externals                 */
/* ================================================================== */

function StateDecoration({ node }: { node: UniverseNode }) {
  const ringRef = useRef<THREE.Mesh>(null);
  const cageRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  const reduced = shared.reducedMotion;
  const r = nodeRadius(node.type);
  const state = node.secState ?? "normal";

  useFrame((s) => {
    if (shared.paused) return;
    const t = s.clock.elapsedTime;
    if (ringRef.current) {
      const m = ringRef.current.material as THREE.MeshBasicMaterial;
      if (state === "threat") {
        m.opacity = reduced ? 0.7 : 0.45 + Math.sin(t * 1.4) * 0.24;
        m.color.set(C.red);
      } else if (state === "suspicious") {
        m.opacity = reduced ? 0.45 : 0.3 + Math.sin(t * 1.1) * 0.12;
        m.color.set(C.amber);
      } else if (state === "blocked") {
        m.opacity = reduced ? 0.4 : 0.24 + Math.sin(t * 1.7) * 0.12;
        m.color.set(C.amberDeep);
      } else if (state === "quarantined") {
        m.opacity = 0.5;
        m.color.set(C.teal);
      } else if (state === "active" && !reduced) {
        m.opacity = 0.16 + Math.sin(t * 1.8) * 0.06;
        m.color.set(C.green);
      } else {
        m.opacity = 0;
      }
    }
    if (cageRef.current) {
      const m = cageRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = state === "quarantined" ? (reduced ? 0.16 : 0.1 + Math.sin(t * 0.9) * 0.04) : 0;
    }
  });

  return (
    <group>
      {state !== "normal" && (
        <mesh ref={ringRef} rotation={[Math.PI / 2, 0, 0]} position={[0, r * 0.15, 0]}>
          <ringGeometry args={[r * 1.12, r * 1.12 + 0.012, 48]} />
          <meshBasicMaterial color={SEC_COLOR[state]} transparent opacity={0} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
        </mesh>
      )}
      {state === "quarantined" && (
        <mesh ref={cageRef}>
          <icosahedronGeometry args={[r * 1.6, 0]} />
          <meshBasicMaterial color={C.teal} wireframe transparent opacity={0} depthWrite={false} toneMapped={false} />
        </mesh>
      )}
    </group>
  );
}

/* ================================================================== */
/* SELECTION HALO                                                      */
/* ================================================================== */

function SelectionHalo({ node }: { node: UniverseNode }) {
  const ref = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  const r = nodeRadius(node.type);
  useFrame((state) => {
    if (ref.current && !shared.paused && !shared.reducedMotion) ref.current.rotation.z = state.clock.elapsedTime * 0.45;
  });
  return (
    <group>
      <mesh ref={ref} rotation={[Math.PI / 1.8, 0, 0]} position={[0, r * 0.2, 0]}>
        <ringGeometry args={[r * 1.26, r * 1.26 + 0.013, 48]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.8} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh rotation={[Math.PI / 1.8, 0, 0]} position={[0, r * 0.2, 0]}>
        <ringGeometry args={[r * 1.14, r * 1.14 + 0.006, 48]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.28} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
    </group>
  );
}

/* ================================================================== */
/* EVENT PULSE — a real event travelling through the relationship      */
/* ================================================================== */

function EventPulse({ node }: { node: UniverseNode }) {
  const ref = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  const r = nodeRadius(node.type);
  useFrame((state) => {
    const mesh = ref.current;
    if (!mesh) return;
    const age = shared.pulseMap.current.get(node.id);
    if (age == null || shared.paused) {
      mesh.visible = false;
      return;
    }
    const p = clamp(age / 1.8, 0, 1);
    const scale = 1 + p * 2.1 + Math.sin(age * 18) * 0.02 * (1 - p);
    mesh.scale.setScalar(scale);
    mesh.position.y = r * 0.2 + p * 0.18;
    const m = mesh.material as THREE.MeshBasicMaterial;
    m.opacity = (1 - p) * 0.7;
    mesh.visible = true;
    void state;
  });
  return (
    <mesh ref={ref} rotation={[Math.PI / 2, 0, 0]} visible={false}>
      <ringGeometry args={[r * 0.9, r * 0.9 + 0.014, 40]} />
      <meshBasicMaterial color={C.cyan} transparent opacity={0} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
    </mesh>
  );
}

/* ================================================================== */
/* ENDPOINT (LAPTOP) — premium monitored device, not a sphere          */
/* ================================================================== */

function EndpointRig({ node, dim, selected, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const shared = useSceneShared();
  const reduced = shared.reducedMotion;
  const scanRef = useRef<THREE.Mesh>(null);
  const beamRef = useRef<THREE.Mesh>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const ring1Ref = useRef<THREE.Mesh>(null);
  const ring2Ref = useRef<THREE.Mesh>(null);
  const ring3Ref = useRef<THREE.Mesh>(null);
  const ifaceCount = Math.max(1, Math.min(6, (node.data.interfaceCount as number) || 1));

  useFrame((state) => {
    if (shared.paused || reduced) return;
    const t = state.clock.elapsedTime;
    if (scanRef.current) {
      scanRef.current.position.y = 0.34 + ((t * 0.06) % 1) * 0.5;
      const m = scanRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = 0.22 * dim;
    }
    if (beamRef.current) {
      const m = beamRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = (0.1 + Math.sin(t * 1.1) * 0.035) * dim;
    }
    if (coreRef.current) {
      const m = coreRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = (0.75 + Math.sin(t * 1.5) * 0.15) * dim;
    }
    if (ring1Ref.current) {
      ring1Ref.current.rotation.y = t * 0.1;
      ring1Ref.current.rotation.x = Math.PI / 2.1 + Math.sin(t * 0.25) * 0.12;
    }
    if (ring2Ref.current) {
      ring2Ref.current.rotation.y = -t * 0.07;
      ring2Ref.current.rotation.x = Math.PI / 1.85 + Math.cos(t * 0.2) * 0.1;
    }
    if (ring3Ref.current) {
      ring3Ref.current.rotation.z = t * 0.14;
      ring3Ref.current.rotation.x = Math.PI / 2.3;
    }
  });

  return (
    <group>
      {/* identity floor ring */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.52, 0]}>
        <ringGeometry args={[0.86, 1.06, 56]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.14 * dim} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.525, 0]}>
        <ringGeometry args={[0.62, 0.63, 40]} />
        <meshBasicMaterial color={C.cyanDeep} transparent opacity={0.18 * dim} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>

      {/* stylized laptop */}
      <RoundedBox args={[1.02, 0.08, 0.78]} radius={0.05} smoothness={4} position={[0, -0.36, 0.06]}>
        <meshStandardMaterial color="#0d1826" metalness={0.82} roughness={0.28} emissive="#0a1320" emissiveIntensity={0.25} />
      </RoundedBox>
      <mesh position={[0, -0.335, -0.3]} rotation={[0, 0, 0]}>
        <boxGeometry args={[0.9, 0.012, 0.06]} />
        <meshStandardMaterial color="#24354a" metalness={0.9} roughness={0.2} />
      </mesh>
      <RoundedBox args={[0.86, 0.56, 0.035]} radius={0.02} smoothness={4} position={[0, 0.3, -0.36]} rotation={[-0.42, 0, 0]}>
        <meshStandardMaterial color="#0a1119" metalness={0.62} roughness={0.2} emissive="#081018" emissiveIntensity={0.35} />
      </RoundedBox>
      <mesh position={[0, 0.32, -0.37]} rotation={[-0.42, 0, 0]}>
        <planeGeometry args={[0.82, 0.52]} />
        <meshBasicMaterial color="#0e2740" transparent opacity={0.4 * dim} side={THREE.DoubleSide} toneMapped={false} />
      </mesh>
      <mesh ref={scanRef} position={[0, 0.28, -0.36]} rotation={[-0.42, 0, 0]}>
        <planeGeometry args={[0.78, 0.012]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.2} toneMapped={false} />
      </mesh>
      {/* screen glow line */}
      <mesh position={[0, 0.568, -0.2]} rotation={[-0.42, 0, 0]}>
        <planeGeometry args={[0.86, 0.014]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.5 * dim} toneMapped={false} />
      </mesh>

      {/* holographic core above the device */}
      <mesh ref={beamRef} position={[0, 0.62, 0]} scale={[1, 1, 1]}>
        <cylinderGeometry args={[0.012, 0.05, 0.95, 10, 1, true]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.1} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh ref={coreRef} position={[0, 1.02, 0.02]} geometry={sharedOcta} scale={[0.11, 0.13, 0.11]}>
        <meshBasicMaterial color={C.cyan} transparent opacity={0.7} toneMapped={false} />
      </mesh>
      <mesh ref={ring1Ref} position={[0, 1.02, 0.02]}>
        <torusGeometry args={[0.2, 0.004, 8, 48]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.5 * dim} toneMapped={false} />
      </mesh>
      <mesh ref={ring2Ref} position={[0, 1.02, 0.02]}>
        <torusGeometry args={[0.27, 0.003, 8, 48]} />
        <meshBasicMaterial color={C.teal} transparent opacity={0.24 * dim} toneMapped={false} />
      </mesh>
      <mesh ref={ring3Ref} position={[0, 1.16, -0.04]}>
        <torusGeometry args={[0.34, 0.002, 6, 44]} />
        <meshBasicMaterial color={C.blue} transparent opacity={0.16 * dim} toneMapped={false} />
      </mesh>

      {/* network interface indicators */}
      {Array.from({ length: ifaceCount }).map((_, i) => {
        const a = -0.4 + (i / ifaceCount) * 0.8;
        return (
          <mesh key={i} position={[Math.cos(a) * 0.42, -0.316, 0.28]}>
            <sphereGeometry args={[0.02, 8, 8]} />
            <meshBasicMaterial color={C.green} transparent opacity={0.85 * dim} toneMapped={false} />
          </mesh>
        );
      })}

      <NodePointer size={1.0} onClick={onSelect} onHover={onHover} onDoubleClick={onSelect} />
      <StateDecoration node={node} />
      <EventPulse node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* ADAPTER — network interface unit                                    */
/* ================================================================== */

function AdapterUnit({ node, dim, selected, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const ledRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  const isUp = (node.data.isUp ?? true) as boolean;
  useFrame((state) => {
    if (!shared.paused && !shared.reducedMotion && ledRef.current) {
      const m = ledRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = (isUp ? 0.75 + Math.sin(state.clock.elapsedTime * 2.2) * 0.18 : 0.5) * dim;
    }
  });

  return (
    <group>
      {/* link card */}
      <RoundedBox args={[0.5, 0.07, 0.3]} radius={0.02} smoothness={3}>
        <meshStandardMaterial color="#0d141d" metalness={0.82} roughness={0.26} emissive="#0a1118" emissiveIntensity={0.2} />
      </RoundedBox>
      {/* gold edge connector */}
      <mesh position={[0, 0.04, -0.16]}>
        <boxGeometry args={[0.4, 0.025, 0.02]} />
        <meshStandardMaterial color="#b89a55" metalness={0.95} roughness={0.18} />
      </mesh>
      {/* heatsink */}
      {[-0.12, 0, 0.12].map((x, i) => (
        <mesh key={i} position={[x, 0, 0.07]}>
          <boxGeometry args={[0.09, 0.04, 0.09]} />
          <meshStandardMaterial color="#1a2432" metalness={0.7} roughness={0.4} />
        </mesh>
      ))}
      <mesh ref={ledRef} position={[0.17, 0.045, 0.12]}>
        <sphereGeometry args={[0.02, 8, 8]} />
        <meshBasicMaterial color={isUp ? C.green : C.amber} transparent opacity={0.85 * dim} toneMapped={false} />
      </mesh>
      <NodePointer size={0.32} onClick={onSelect} onHover={onHover} />
      <StateDecoration node={node} />
      <EventPulse node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* GATEWAY — infrastructure router object                              */
/* ================================================================== */

function GatewayRouter({ node, dim, selected, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const busRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  useFrame((state) => {
    if (shared.paused || !busRef.current) return;
    const m = busRef.current.material as THREE.MeshBasicMaterial;
    m.opacity = (0.6 + Math.sin(state.clock.elapsedTime * 1.4) * 0.2) * dim;
  });

  return (
    <group>
      <RoundedBox args={[0.62, 0.2, 0.46]} radius={0.03} smoothness={3}>
        <meshStandardMaterial color="#121820" metalness={0.72} roughness={0.3} emissive="#0c131c" emissiveIntensity={0.35} />
      </RoundedBox>
      {/* front activity bar */}
      <mesh ref={busRef} position={[0, 0.045, 0.232]}>
        <planeGeometry args={[0.5, 0.05]} />
        <meshBasicMaterial color="#ffe3a0" transparent opacity={0.6} toneMapped={false} />
      </mesh>
      {/* port LEDs */}
      {[-0.16, -0.05, 0.06, 0.17].map((x, i) => (
        <mesh key={i} position={[x, -0.03, 0.19]}>
          <sphereGeometry args={[0.014, 8, 8]} />
          <meshBasicMaterial color={i % 2 ? C.green : C.blue} transparent opacity={0.8 * dim} toneMapped={false} />
        </mesh>
      ))}
      {/* antennas */}
      <mesh position={[-0.2, 0.15, 0.08]} rotation={[0.3, 0, 0]}>
        <cylinderGeometry args={[0.013, 0.013, 0.12, 8]} />
        <meshStandardMaterial color="#2a2a2a" metalness={0.6} roughness={0.4} />
      </mesh>
      <mesh position={[0.2, 0.15, 0.08]} rotation={[0.3, 0, 0]}>
        <cylinderGeometry args={[0.013, 0.013, 0.12, 8]} />
        <meshStandardMaterial color="#2a2a2a" metalness={0.6} roughness={0.4} />
      </mesh>
      <mesh position={[-0.2, 0.2, 0.08]}>
        <sphereGeometry args={[0.02, 8, 8]} />
        <meshBasicMaterial color="#3a3a3a" transparent opacity={0.9} />
      </mesh>
      <mesh position={[0.2, 0.2, 0.08]}>
        <sphereGeometry args={[0.02, 8, 8]} />
        <meshBasicMaterial color="#3a3a3a" transparent opacity={0.9} />
      </mesh>
      <NodePointer size={0.4} onClick={onSelect} onHover={onHover} />
      <StateDecoration node={node} />
      <EventPulse node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* DNS SERVICE                                                         */
/* ================================================================== */

function DnsService({ node, dim, selected, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const ringRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  useFrame((state) => {
    if (shared.paused || shared.reducedMotion || !ringRef.current) return;
    ringRef.current.rotation.y = state.clock.elapsedTime * 0.28;
  });

  return (
    <group>
      <mesh position={[0, -0.08, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <cylinderGeometry args={[0.19, 0.24, 0.05, 20]} />
        <meshStandardMaterial color="#101826" metalness={0.75} roughness={0.3} />
      </mesh>
      <RoundedBox args={[0.32, 0.13, 0.32]} radius={0.016} smoothness={3} position={[0, 0.015, 0]}>
        <meshStandardMaterial color="#0e1622" metalness={0.78} roughness={0.28} emissive="#0a1018" emissiveIntensity={0.3} />
      </RoundedBox>
      <mesh ref={ringRef} position={[0, 0.1, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <torusGeometry args={[0.2, 0.004, 6, 28]} />
        <meshBasicMaterial color={C.purple} transparent opacity={0.4 * dim} toneMapped={false} />
      </mesh>
      <mesh position={[0, 0.09, 0]} geometry={sharedOcta} scale={[0.06, 0.07, 0.06]}>
        <meshBasicMaterial color={C.purple} transparent opacity={0.8 * dim} toneMapped={false} />
      </mesh>
      <NodePointer size={0.3} onClick={onSelect} onHover={onHover} />
      <StateDecoration node={node} />
      <EventPulse node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* NEIGHBOR — LAN peer unit                                            */
/* ================================================================== */

function NeighborUnit({ node, dim, selected, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const ledRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  useFrame((state) => {
    if (!shared.paused && !shared.reducedMotion && ledRef.current) {
      const m = ledRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = (0.5 + Math.sin(state.clock.elapsedTime * 1.2) * 0.15) * dim;
    }
  });
  return (
    <group>
      <RoundedBox args={[0.3, 0.16, 0.06]} radius={0.02} smoothness={3}>
        <meshStandardMaterial color="#0d151f" metalness={0.6} roughness={0.38} emissive="#0a1018" emissiveIntensity={0.18} />
      </RoundedBox>
      <mesh ref={ledRef} position={[0.09, 0.015, 0.035]}>
        <sphereGeometry args={[0.02, 8, 8]} />
        <meshBasicMaterial color={C.cyan} transparent opacity={0.4 * dim} toneMapped={false} />
      </mesh>
      <mesh position={[-0.08, 0.02, 0.035]}>
        <boxGeometry args={[0.08, 0.03, 0.005]} />
        <meshBasicMaterial color={C.green} transparent opacity={0.55 * dim} />
      </mesh>
      <NodePointer size={0.22} onClick={onSelect} onHover={onHover} />
      <StateDecoration node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* PROCESS — application card with real/generic executable icon        */
/* ================================================================== */

const procAccentCache = new Map<string, string>();
function procAccent(name: string): string {
  let a = procAccentCache.get(name);
  if (a) return a;
  a = GAL[classifyProcess(name).gallery] || C.slate;
  procAccentCache.set(name, a);
  return a;
}

function ProcessCard({ node, dim, selected, hovered, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  hovered: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const shared = useSceneShared();
  const name = (node.data.name as string) || node.label || "PROCESS";
  const pid = node.data.pid as number;
  const accent = procAccent(name);
  const listening = ((node.data.listeningCount as number) || 0) > 0;
  const connCount = (node.data.connectionCount as number) || node.connections || 0;
  const iconPath = (node.data.executablePath as string | undefined) || (node.data.path as string | undefined);
  const realIcon = useRealIconTexture(iconPath, pid);
  const glyphColor = accent;
  const glyphKind = getProcGlyph(name);
  const glyphTex = useMemo(() => makeGlyphTexture(glyphKind, glyphColor), [glyphKind, glyphColor]);
  const genericTex = useMemo(() => makeExecIconTexture(name, accent), [name, accent]);

  const glowRef = useRef<THREE.Mesh>(null);
  const hoverRef = useRef<THREE.Mesh>(null);
  const w = 0.82;
  const h = 0.55;

  useFrame((state) => {
    if (shared.paused || !glowRef.current) return;
    const gm = glowRef.current.material as THREE.MeshBasicMaterial;
    gm.opacity = (selected ? 0.14 : hovered ? 0.1 : Math.min(0.06, 0.028 + Math.min(connCount, 8) * 0.006)) * dim
      + Math.sin(state.clock.elapsedTime * 1.1 + node.x) * 0.008;
    if (hoverRef.current) {
      const hm = hoverRef.current.material as THREE.MeshBasicMaterial;
      hm.opacity = (hovered || selected ? 0.9 : 0.45) * dim;
    }
  });

  const displayName = name.replace(/\.exe$/i, "");

  return (
    <group>
      <Billboard>
        <group position={[0, -0.26, 0]}>
          <mesh ref={glowRef} position={[0, 0, -0.03]}>
            <planeGeometry args={[w + 0.16, h + 0.18]} />
            <meshBasicMaterial color={accent} transparent opacity={0.04} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
          </mesh>
          <RoundedBox args={[w, h, 0.035]} radius={0.026} smoothness={3}>
            <meshStandardMaterial color={C.panel} metalness={0.5} roughness={0.42} emissive="#0a0f16" emissiveIntensity={0.25} />
          </RoundedBox>
          {/* accent keyline */}
          <mesh position={[0, h / 2 - 0.006, 0.02]}>
            <planeGeometry args={[w - 0.03, 0.012]} />
            <meshBasicMaterial color={accent} transparent opacity={0.75 * dim} toneMapped={false} />
          </mesh>
          {/* icon tile */}
          <group position={[-w / 2 + 0.175, 0.045, 0.024]}>
            <RoundedBox args={[0.3, 0.3, 0.02]} radius={0.012} smoothness={3}>
              <meshStandardMaterial color="#0b121b" metalness={0.6} roughness={0.3} emissive="#0a1018" emissiveIntensity={0.4} />
            </RoundedBox>
            <mesh position={[0, 0, 0.012]}>
              <planeGeometry args={[0.28, 0.28]} />
              <meshBasicMaterial map={realIcon || genericTex || glyphTex} transparent opacity={0.95 * dim} toneMapped={false} />
            </mesh>
            <mesh position={[0.132, 0.132, 0.014]} rotation={[0, 0, Math.PI / 4]}>
              <boxGeometry args={[0.028, 0.028, 0.004]} />
              <meshBasicMaterial color={accent} transparent opacity={0.8 * dim} />
            </mesh>
          </group>
          {/* divider */}
          <mesh position={[-0.012, 0, 0.02]}>
            <planeGeometry args={[0.002, h - 0.1]} />
            <meshBasicMaterial color={C.dim} transparent opacity={0.55 * dim} />
          </mesh>
          {/* name + meta */}
          <group position={[0.1, 0.1, 0.022]}>
            <Text fontSize={0.075} color={selected || hovered ? "#eaf6ff" : "#c6d6e6"} anchorX="left" anchorY="middle" maxWidth={0.58} outlineWidth={0.004} outlineColor="#02060c" fillOpacity={0.92 * dim}>
              {displayName}
            </Text>
          </group>
          <group position={[0.1, -0.04, 0.022]}>
            <Text fontSize={0.045} color="#7c93ab" anchorX="left" anchorY="middle" maxWidth={0.58} fillOpacity={0.9 * dim}>
              {`PID ${pid} · ${connCount} conn${connCount === 1 ? "" : "s"}`}
            </Text>
          </group>
          {/* listening badge */}
          {listening && (
            <group position={[w / 2 - 0.09, -h / 2 + 0.04, 0.024]}>
              <mesh>
                <sphereGeometry args={[0.016, 8, 8]} />
                <meshBasicMaterial color={C.green} transparent opacity={0.9 * dim} toneMapped={false} />
              </mesh>
            </group>
          )}
          {/* hover keyline */}
          <mesh ref={hoverRef} position={[0, 0, -0.001]}>
            <planeGeometry args={[w + 0.02, h + 0.02]} />
            <meshBasicMaterial color={accent} transparent opacity={0.45} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
          </mesh>
          <mesh
            position={[0, 0, 0.02]}
            onPointerOver={(e) => {
              e.stopPropagation();
              onHover(true);
            }}
            onPointerOut={() => onHover(false)}
            onPointerDown={(e) => e.stopPropagation()}
            onClick={(e) => {
              e.stopPropagation();
              onSelect();
            }}
          >
            <planeGeometry args={[w + 0.14, h + 0.14]} />
            <meshBasicMaterial transparent opacity={0} depthWrite={false} />
          </mesh>
          <StateDecoration node={node} />
        </group>
      </Billboard>
      <EventPulse node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* PORT — socket marker                                                */
/* ================================================================== */

function PortSocket({ node, dim, selected, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const coreRef = useRef<THREE.Mesh>(null);
  const ringRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  const listening = !!node.listening;

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    if (shared.paused) return;
    if (coreRef.current) {
      const m = coreRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = (listening ? 0.7 + Math.sin(t * 1.6) * 0.22 : 0.4) * dim;
    }
    if (ringRef.current) {
      ringRef.current.rotation.y = t * (listening ? 0.5 : 0.2);
      const m = ringRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = (listening ? 0.5 + Math.sin(t * 1.5) * 0.15 : 0.22) * dim;
    }
  });

  return (
    <group>
      <mesh geometry={sharedHex} rotation={[0, 0, Math.PI / 2]} scale={[0.07, 0.09, 0.07]}>
        <meshStandardMaterial color="#0e1620" metalness={0.78} roughness={0.3} emissive="#0a0f16" emissiveIntensity={0.4} />
      </mesh>
      <mesh ref={coreRef} position={[0, 0, 0.05]}>
        <sphereGeometry args={[0.035, 8, 8]} />
        <meshBasicMaterial color={listening ? C.green : C.cyan} transparent opacity={0.6} toneMapped={false} />
      </mesh>
      <mesh ref={ringRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0, 0.02]}>
        <torusGeometry args={[0.075, 0.004, 6, 20]} />
        <meshBasicMaterial color={listening ? C.green : C.cyan} transparent opacity={0.4} toneMapped={false} />
      </mesh>
      <NodePointer size={0.2} onClick={onSelect} onHover={onHover} />
      <StateDecoration node={node} />
      <EventPulse node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* REMOTE HOST — compact external endpoint                             */
/* ================================================================== */

function RemoteHost({ node, dim, selected, hovered, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  hovered: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const ledRef = useRef<THREE.Mesh>(null);
  const bodyRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  const established = node.data.state === "ESTABLISHED";
  const resolved = !!node.data.hostname && node.data.hostname !== "UNRESOLVED";
  const tint = node.secState === "suspicious" ? C.amber : node.secState === "threat" ? C.red : C.purple;

  useFrame((state) => {
    if (shared.paused) return;
    const t = state.clock.elapsedTime;
    if (ledRef.current) {
      const m = ledRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = (established ? 0.8 + Math.sin(t * 1.5) * 0.16 : 0.36) * dim;
    }
    if (bodyRef.current && !shared.reducedMotion) {
      bodyRef.current.rotation.y = t * 0.18;
    }
  });

  return (
    <group>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.2, 0]}>
        <ringGeometry args={[0.22, 0.32, 36]} />
        <meshBasicMaterial color={C.purpleDeep} transparent opacity={0.14 * dim} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh ref={bodyRef} geometry={sharedOcta} scale={[0.16, 0.22, 0.16]}>
        <meshStandardMaterial color="#171028" metalness={0.7} roughness={0.3} emissive="#140d24" emissiveIntensity={0.5} />
      </mesh>
      <mesh geometry={sharedOcta} scale={[0.07, 0.09, 0.07]} position={[0, 0.02, 0]}>
        <meshBasicMaterial color={tint} transparent opacity={(selected || hovered ? 0.9 : 0.6) * dim} toneMapped={false} />
      </mesh>
      {/* directional chevron — external world marker */}
      <mesh ref={ledRef} position={[0, 0.185, 0]}>
        <sphereGeometry args={[0.024, 10, 10]} />
        <meshBasicMaterial color={established ? C.green : C.purple} transparent opacity={0.6} toneMapped={false} />
      </mesh>
      <mesh position={[0, 0.01, 0]} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[0.26, 0.003, 6, 32]} />
        <meshBasicMaterial color={C.purpleSoft} transparent opacity={0.18 * dim} toneMapped={false} />
      </mesh>
      {resolved && !selected && !hovered && (
        <Billboard position={[0, 0.34, 0]}>
          <Text fontSize={0.055} color={C.purple} anchorX="center" anchorY="middle" outlineWidth={0.006} outlineColor="#04070c" fillOpacity={0.7 * dim}>
            {(node.label || "").slice(0, 22)}
          </Text>
        </Billboard>
      )}
      <NodePointer size={0.32} onClick={onSelect} onHover={onHover} />
      <StateDecoration node={node} />
      <EventPulse node={node} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* INTERNET — distant atmospheric band (no sphere)                     */
/* ================================================================== */

const internetGrad = (() => {
  const S = 512;
  const c = document.createElement("canvas");
  c.width = S;
  c.height = S;
  const ctx = c.getContext("2d")!;
  const g = ctx.createRadialGradient(S / 2, S * 0.42, 20, S / 2, S / 2, S / 2);
  g.addColorStop(0, "rgba(96,74,190,0.42)");
  g.addColorStop(0.5, "rgba(48,34,110,0.18)");
  g.addColorStop(1, "rgba(10,8,24,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, S, S);
  // faint connection rings
  ctx.strokeStyle = "rgba(160,123,224,0.2)";
  ctx.lineWidth = 1.5;
  for (const r of [90, 150, 210]) {
    ctx.beginPath();
    ctx.arc(S / 2, S * 0.42, r, 0, Math.PI * 2);
    ctx.stroke();
  }
  ctx.strokeStyle = "rgba(120,96,210,0.25)";
  ctx.beginPath();
  ctx.ellipse(S / 2, S * 0.42, 150, 70, 0, 0, Math.PI * 2);
  ctx.stroke();
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 4;
  return t;
})();

function InternetBand({ node, dim, selected, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  const shared = useSceneShared();
  const driftRef = useRef<THREE.Points>(null);
  const pts = useMemo(() => {
    const count = 44;
    const pos = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const r = 6 + Math.random() * 11;
      const a = Math.random() * Math.PI * 2;
      const e = Math.random() * Math.PI * 0.5 - Math.PI * 0.25;
      pos[i * 3] = Math.cos(a) * Math.cos(e) * r;
      pos[i * 3 + 1] = Math.sin(e) * r * 0.5 + 5;
      pos[i * 3 + 2] = Math.sin(a) * Math.cos(e) * r - 15;
    }
    return pos;
  }, []);
  useFrame((state) => {
    if (shared.paused || shared.reducedMotion) return;
    const t = state.clock.elapsedTime;
    const m = driftRef.current?.material as THREE.PointsMaterial | undefined;
    if (m) m.opacity = (0.26 + Math.sin(t * 0.3) * 0.06) * dim;
    if (driftRef.current) driftRef.current.rotation.y = t * 0.006;
  });

  return (
    <group>
      <mesh position={[0, 5, -15]} rotation={[0, 0, 0]}>
        <planeGeometry args={[46, 26]} />
        <meshBasicMaterial map={internetGrad} transparent opacity={0.85 * dim} depthWrite={false} toneMapped={false} color="#c9b7ff" />
      </mesh>
      {/* horizon line */}
      <mesh position={[0, 5, -14.6]}>
        <planeGeometry args={[60, 0.05]} />
        <meshBasicMaterial color={C.purpleSoft} transparent opacity={0.2 * dim} depthWrite={false} toneMapped={false} />
      </mesh>
      <points ref={driftRef}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[pts, 3]} />
        </bufferGeometry>
        <pointsMaterial color="#b9a5f0" size={0.07} transparent opacity={0.26} sizeAttenuation depthWrite={false} />
      </points>
      <NodePointer size={3.4} onClick={onSelect} onHover={onHover} />
      {selected && <SelectionHalo node={node} />}
    </group>
  );
}

/* ================================================================== */
/* NODE VIEW dispatcher                                                */
/* ================================================================== */

function NodeView({ node, dim, selected, hovered, onSelect, onHover }: {
  node: UniverseNode;
  dim: number;
  selected: boolean;
  hovered: boolean;
  onSelect: () => void;
  onHover: (h: boolean) => void;
}) {
  switch (node.type) {
    case "laptop":
      return <EndpointRig node={node} dim={dim} selected={selected} onSelect={onSelect} onHover={onHover} />;
    case "adapter":
      return <AdapterUnit node={node} dim={dim} selected={selected} onSelect={onSelect} onHover={onHover} />;
    case "gateway":
      return <GatewayRouter node={node} dim={dim} selected={selected} onSelect={onSelect} onHover={onHover} />;
    case "dns":
      return <DnsService node={node} dim={dim} selected={selected} onSelect={onSelect} onHover={onHover} />;
    case "neighbor":
      return <NeighborUnit node={node} dim={dim} selected={selected} onSelect={onSelect} onHover={onHover} />;
    case "process":
      return <ProcessCard node={node} dim={dim} selected={selected} hovered={hovered} onSelect={onSelect} onHover={onHover} />;
    case "port":
      return <PortSocket node={node} dim={dim} selected={selected} onSelect={onSelect} onHover={onHover} />;
    case "remote":
      return <RemoteHost node={node} dim={dim} selected={selected} hovered={hovered} onSelect={onSelect} onHover={onHover} />;
    case "internet":
      return <InternetBand node={node} dim={dim} selected={selected} onSelect={onSelect} onHover={onHover} />;
    default:
      return null;
  }
}

/* ================================================================== */
/* GHOST NODE — despawn lifecycle (fade + scale down)                  */
/* ================================================================== */

function GhostNodeView({ node, onDone }: { node: UniverseNode; onDone: () => void }) {
  const ref = useRef<THREE.Group>(null);
  const tint = nodeTint(node.type);
  const done = useRef(false);
  const shared = useSceneShared();

  useEffect(() => {
    const id = window.setTimeout(() => {
      done.current = true;
      onDone();
    }, 1150);
    return () => window.clearTimeout(id);
  }, [onDone]);

  useFrame((state) => {
    if (shared.paused) return;
    const g = ref.current;
    if (!g) return;
    const age = Math.min(state.clock.getDelta() * 0 + 0.012, 0.05);
    void age;
    let s = g.scale.x;
    s -= 0.85 * 0.016;
    g.scale.setScalar(Math.max(0.001, s));
    const m0 = (g.children[0] as THREE.Mesh).material as THREE.MeshBasicMaterial;
    m0.opacity = Math.max(0, m0.opacity - 0.016);
  });

  return (
    <group ref={ref} position={[node.x, node.y, node.z]} scale={1}>
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.12, 0.16, 24]} />
        <meshBasicMaterial color={tint} transparent opacity={0.55} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh scale={1.6} rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.1, 0.102, 24]} />
        <meshBasicMaterial color={tint} transparent opacity={0.4} side={THREE.DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
    </group>
  );
}

/* ================================================================== */
/* LINK TUBE — curved directional connection                           */
/* ================================================================== */

function LinkTube({ link, anim, dim, selected, modelNodes, flowBoost, onClick }: {
  link: UniverseLink;
  anim: LinkAnim;
  dim: number;
  selected: boolean;
  modelNodes: UniverseNode[];
  flowBoost: number;
  onClick: () => void;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const matRef = useRef<THREE.MeshBasicMaterial>(null);
  const shared = useSceneShared();
  const paused = shared.paused;
  const reduced = shared.reducedMotion;
  const baseColor = linkColorFor(link, selected);
  const arrowRef = useRef<THREE.Mesh>(null);
  const arrowPos = useRef(new THREE.Vector3());
  const arrowTan = useRef(new THREE.Vector3());
  const flowMatRef = useRef<THREE.MeshBasicMaterial>(null);

  useEffect(() => {
    const fromNode = modelNodes.find((n) => n.id === link.from);
    const toNode = modelNodes.find((n) => n.id === link.to);
    if (!fromNode || !toNode || !anim.curve) return;
    const f: [number, number, number] = [fromNode.x, fromNode.y, fromNode.z];
    const t: [number, number, number] = [toNode.x, toNode.y, toNode.z];
    if (f[0] !== anim.from[0] || f[1] !== anim.from[1] || f[2] !== anim.from[2] ||
        t[0] !== anim.to[0] || t[1] !== anim.to[1] || t[2] !== anim.to[2]) {
      const old = anim.geometry;
      const arch = link.edge === "remote" ? 5.2 : link.edge === "infra" ? 3.4 : 2.0;
      const { curve, points } = buildCurve(f, t, arch);
      anim.curve = curve;
      anim.points = points;
      anim.geometry = new THREE.TubeGeometry(curve, 24, 0.007, 6, false);
      if (old) old.dispose();
    }
  }, [modelNodes, link, anim]);

  useEffect(() => {
    const amount = packetAmountFor(link, flowBoost);
    const pts = anim.points;
    const speed = 0.2 + hf(link.id) * 0.1;
    const key = `${link.id}|${link.state}|${Math.round(flowBoost)}|${link.secState ?? ""}|${amount}`;
    const store = shared.packetStore.current;
    const existing = store.get(link.id);
    if (existing && existing.key === key) return;
    if (amount <= 0) {
      if (existing) store.delete(link.id);
      return;
    }
    const offsets: number[] = [];
    for (let i = 0; i < amount; i++) offsets.push((i + hf(link.id + i)) / amount);
    store.set(link.id, {
      key,
      points: pts,
      amount,
      speed,
      dir: link.direction === "inbound" ? -1 : 1,
      color: new THREE.Color(link.secState === "active" ? C.green : baseColor),
      offsets,
    });
    return () => {
      if (shared.packetStore.current.get(link.id)?.key === key)
        shared.packetStore.current.delete(link.id);
    };
  }, [link, flowBoost, anim.points, baseColor, shared.packetStore]);

  const showArrow = link.edge === "remote" && !reduced && (link.state === "flowing" || selected || dim < 0.9);

  useFrame((state, delta) => {
    if (paused) return;
    const dt = Math.min(delta, 0.05);
    anim.phaseT += dt;
    anim.burst = Math.max(0, anim.burst - dt * 0.5);
    if (anim.phase === "form" && anim.phaseT > 1.15) {
      anim.phase = anim.link.state === "flowing" ? "flow" : "idle";
      anim.phaseT = 0;
    }
    if (anim.phase === "close" && anim.dying) {
      anim.alpha = Math.max(0, anim.alpha - dt * 1.25);
      if (matRef.current) matRef.current.opacity = anim.alpha * dim;
      if (flowMatRef.current) flowMatRef.current.opacity = anim.alpha * dim * 0.35;
      return;
    }
    const target = computedTargetAlpha(anim, dim, selected);
    anim.alpha = THREE.MathUtils.damp(anim.alpha, target, 2.4, dt);
    if (matRef.current) {
      matRef.current.opacity = anim.alpha * dim;
      matRef.current.color.set(selected ? C.white : baseColor);
    }
    if (flowMatRef.current) {
      flowMatRef.current.opacity = anim.alpha * dim * 0.22;
      flowMatRef.current.color.set(baseColor);
    }
    if (arrowRef.current && showArrow && anim.points.length > 1) {
      const t = 0.9;
      const i = Math.min(anim.points.length - 2, Math.floor(t * (anim.points.length - 1)));
      pointAt(anim.points, t, arrowPos.current);
      arrowTan.current.subVectors(anim.points[i + 1], anim.points[i]).normalize();
      arrowRef.current.position.copy(arrowPos.current);
      arrowRef.current.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, -1), arrowTan.current);
      const m = arrowRef.current.material as THREE.MeshBasicMaterial;
      m.opacity = Math.max(0, Math.min(0.6, anim.alpha * dim));
    }
    void state;
  });

  return (
    <group>
      {anim.curve && (
        <mesh ref={meshRef} geometry={anim.geometry || undefined} onClick={(e) => {
          e.stopPropagation();
          onClick();
        }}>
          <meshBasicMaterial ref={matRef} color={baseColor} transparent opacity={0.001} depthWrite={false} toneMapped={false} />
        </mesh>
      )}
      {anim.curve && (link.state === "flowing" || selected) && (
        <mesh geometry={anim.geometry || undefined}>
          <meshBasicMaterial ref={flowMatRef} color={baseColor} transparent opacity={0.001} depthWrite={false} toneMapped={false} />
        </mesh>
      )}
      {showArrow && (
        <mesh ref={arrowRef} geometry={sharedCone} scale={[0.022, 0.04, 0.02]}>
          <meshBasicMaterial color="#d9b8ff" transparent opacity={0.001} depthWrite={false} toneMapped={false} />
        </mesh>
      )}
    </group>
  );
}

/* ================================================================== */
/* GHOST LINK — graceful connection removal                            */
/* ================================================================== */

function GhostLink({ anim, dim, onDone }: { anim: LinkAnim; dim: number; onDone?: () => void }) {
  const matRef = useRef<THREE.MeshBasicMaterial>(null);
  const meshRef = useRef<THREE.Mesh>(null);
  const shared = useSceneShared();
  const paused = shared.paused;
  const done = useRef(false);

  useEffect(() => () => {
    if (anim.geometry && !done.current) {
      anim.geometry.dispose();
      anim.geometry = null;
      anim.curve = null;
    }
  }, [anim]);

  useFrame((state, delta) => {
    if (paused) return;
    const dt = Math.min(delta, 0.05);
    anim.alpha = Math.max(0, anim.alpha - dt * 1.05);
    if (matRef.current) matRef.current.opacity = anim.alpha * dim;
    if (anim.alpha <= 0.005) {
      done.current = true;
      if (anim.geometry) {
        anim.geometry.dispose();
        anim.geometry = null;
        anim.curve = null;
      }
      if (meshRef.current) meshRef.current.visible = false;
      onDone?.();
    }
    void state;
  });

  return (
    <group>
      {anim.curve && (
        <mesh ref={meshRef} geometry={anim.geometry || undefined}>
          <meshBasicMaterial ref={matRef} color={C.slate} transparent opacity={0.001} depthWrite={false} toneMapped={false} />
        </mesh>
      )}
    </group>
  );
}

/* ================================================================== */
/* PACKET LAYER — instanced directional flow along real paths           */
/* ================================================================== */

const MAX_PACKETS = 208;

function PacketLayer({ flowBoost }: { flowBoost: number }) {
  const meshRef = useRef<THREE.InstancedMesh>(null);
  const shared = useSceneShared();
  const paused = shared.paused;
  const reduced = shared.reducedMotion;
  const qualityRef = shared.qualityRef;
  const mat = useRef(new THREE.Matrix4());
  const tmp = useRef(new THREE.Vector3());
  const lastBoost = useRef(0);
  useEffect(() => {
    lastBoost.current = flowBoost;
  }, [flowBoost]);

  useFrame((_, delta) => {
    const mesh = meshRef.current;
    if (!mesh) return;
    if (paused || reduced) {
      mesh.count = 0;
      return;
    }
    const dt = Math.min(delta, 0.05);
    const q = qualityRef.current;
    const cap = q === "high" ? MAX_PACKETS : q === "medium" ? 120 : 52;
    const boost = lastBoost.current;
    let used = 0;
    const m = mat.current;
    const out = tmp.current;
    for (const bind of shared.packetStore.current.values()) {
      if (used >= cap) break;
      const n = Math.min(bind.amount, cap - used);
      for (let k = 0; k < n; k++) {
        bind.offsets[k] = (bind.offsets[k] + bind.dir * bind.speed * dt) % 1;
        if (bind.offsets[k] < 0) bind.offsets[k] += 1;
        pointAt(bind.points, bind.offsets[k], out);
        m.makeTranslation(out.x, out.y, out.z);
        const fade = 0.6 + 0.4 * Math.sin(bind.offsets[k] * Math.PI);
        const s = 0.014 * fade * (1 + boost * 0.05);
        m.scale(new THREE.Vector3(s, s, s));
        mesh.setMatrixAt(used, m);
        mesh.setColorAt(used, bind.color);
        used++;
      }
    }
    mesh.count = used;
    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  });

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, MAX_PACKETS]} frustumCulled={false}>
      <sphereGeometry args={[1, 6, 5]} />
      <meshBasicMaterial color="#ffffff" transparent opacity={0.8} depthWrite={false} toneMapped={false} />
    </instancedMesh>
  );
}

/* ================================================================== */
/* LABELS — intelligent, camera-facing, overlap-rejected, LOD          */
/* ================================================================== */

type LabelEntry = { priority: number; rect: { x: number; y: number; w: number; h: number } | null; active: boolean };
const labelContext: { entries: Map<string, LabelEntry> } = { entries: new Map() };

function labelPriority(node: UniverseNode): number {
  switch (node.type) {
    case "internet": return 100;
    case "laptop": return 96;
    case "gateway": return 90;
    case "dns": return 60;
    case "process": return 50 + clamp(node.connections, 0, 10);
    case "remote": return 40 + (node.data.state === "ESTABLISHED" ? 3 : 0) + (node.data.hostname && node.data.hostname !== "UNRESOLVED" ? 2 : 0);
    case "adapter": return 30;
    case "neighbor": return 24;
    case "port": return node.listening ? 20 : 14;
    default: return 18;
  }
}

function NodeLabel({ node, hovered, selected }: {
  node: UniverseNode;
  hovered: boolean;
  selected: boolean;
}) {
  const groupRef = useRef<THREE.Group>(null);
  const { camera, size, gl } = useThree();
  const world = useRef(new THREE.Vector3());
  const ndc = useRef(new THREE.Vector3());
  const entryId = `label-${node.id}`;
  const isProcess = node.type === "process";

  const baseCol = selected
    ? C.cyan
    : hovered
      ? C.white
      : node.type === "remote"
        ? C.purpleSoft
        : node.type === "dns"
          ? C.purple
          : isProcess
            ? "#cfe4f4"
            : node.type === "adapter"
              ? C.green
              : node.type === "gateway"
                ? C.blue
                : node.type === "internet"
                  ? C.purpleSoft
                  : C.muted;
  const boosted = (hovered ? 600 : 0) + (selected ? 500 : 0);
  const display = node.type === "port" ? `:${node.label}` : node.label;
  const textLen = Math.max(display.length, 3);
  const fontSize = labelFontFor(node.type);
  const threshold = labelThresholdFor(node.type);

  useFrame((state) => {
    const g = groupRef.current;
    if (!g) return;
    const d = camera.position.distanceTo(g.getWorldPosition(world.current));
    const far = d > threshold;
    const entry = labelContext.entries.get(entryId) || { priority: labelPriority(node) + boosted, rect: null, active: false };
    if (far) {
      entry.rect = null;
      entry.priority = labelPriority(node) + boosted;
      labelContext.entries.set(entryId, entry);
      if (g.visible) g.visible = false;
      return;
    }
    ndc.current.copy(g.getWorldPosition(world.current)).project(camera);
    const px = ndc.current.x * 0.5 * size.width + size.width * 0.5;
    const py = -ndc.current.y * 0.5 * size.height + size.height * 0.5;
    if (ndc.current.z > 1 || ndc.current.z < -1 || px < -size.width * 0.3 || px > size.width * 1.3 || py < -size.height * 0.3 || py > size.height * 1.3) {
      entry.rect = null;
      entry.priority = labelPriority(node) + boosted;
      labelContext.entries.set(entryId, entry);
      if (g.visible) g.visible = false;
      return;
    }
    const pr = gl.getPixelRatio();
    const depth = camera.position.distanceTo(world.current);
    const vFov = camera instanceof THREE.PerspectiveCamera ? camera.fov : 40;
    const scalePx = (size.height * pr) / (2 * Math.tan(THREE.MathUtils.degToRad(vFov) * 0.5)) / depth;
    const w = textLen * fontSize * scalePx * 0.42;
    const hh = fontSize * scalePx * 0.22;
    entry.rect = { x: px * pr - w / 2, y: py * pr - hh, w, h: hh * 2 };
    entry.priority = labelPriority(node) + boosted;
    labelContext.entries.set(entryId, entry);
    const entries = [...labelContext.entries.values()];
    entries.sort((a, b) => b.priority - a.priority);
    const chosen: Array<{ x: number; y: number; w: number; h: number }> = [];
    const cap = labelCapFor();
    let picked = true;
    for (const e of entries) {
      if (chosen.length >= cap) break;
      if (e.rect == null) continue;
      let overlap = false;
      for (const c of chosen) {
        const ox = Math.max(0, Math.min(e.rect.x + e.rect.w, c.x + c.w) - Math.max(e.rect.x, c.x));
        const oy = Math.max(0, Math.min(e.rect.y + e.rect.h, c.y + c.h) - Math.max(e.rect.y, c.y));
        if (ox * oy > 8) {
          overlap = true;
          break;
        }
      }
      if (!overlap) {
        chosen.push(e.rect);
        if (e === entry) picked = true;
        else void 0;
      } else if (e === entry) {
        picked = false;
      }
    }
    entry.active = picked;
    g.visible = true;
    const cur = g.scale.x;
    const nx = THREE.MathUtils.damp(cur, picked ? 1 : 0, picked ? 6.5 : 9, Math.min(state.clock.getDelta(), 0.05));
    g.scale.setScalar(Math.max(0.0001, nx));
    if (nx < 0.15) g.visible = false;
  });

  return (
    <group position={[node.x, node.y + nodeRadius(node.type) + 0.16, node.z]}>
      <group ref={groupRef} scale={0.0001}>
        <group position={[0, 0.12, 0]}>
          <Billboard>
            <Text
              fontSize={fontSize}
              color={baseCol}
              anchorX="center"
              anchorY="bottom"
              maxWidth={isProcess ? 1.3 : 2.2}
              outlineWidth={0.006}
              outlineColor="#02050a"
            >
              {display}
            </Text>
          </Billboard>
        </group>
      </group>
    </group>
  );
}

function labelFontFor(type: string): number {
  switch (type) {
    case "port": return 0.055;
    case "adapter": return 0.06;
    case "neighbor": return 0.055;
    case "remote": return 0.062;
    case "dns": return 0.075;
    case "process": return 0.078;
    case "gateway": return 0.11;
    case "internet": return 0.15;
    case "laptop": return 0.12;
    default: return 0.07;
  }
}

function labelThresholdFor(type: string): number {
  switch (type) {
    case "laptop": return 60;
    case "internet": return 80;
    case "gateway": return 55;
    case "dns": return 42;
    case "process": return 22;
    case "remote": return 20;
    case "adapter": return 12;
    case "neighbor": return 12;
    case "port": return 10;
    default: return 16;
  }
}

const sharedQuality = { level: "high" as QualityLevel };
function labelCapFor(): number {
  const l = sharedQuality.level;
  return l === "high" ? 14 : l === "medium" ? 10 : 6;
}

/* ================================================================== */
/* TOOLTIP                                                             */
/* ================================================================== */

function TooltipHost({ node }: { node: UniverseNode }) {
  let body: React.ReactNode;
  if (node.type === "process") {
    body = (
      <>
        <div className="u-tip-title">{node.label}.exe</div>
        <div className="u-tip-line">PID {String(node.data.pid)}</div>
        <div className="u-tip-line">{node.connections} connection{node.connections === 1 ? "" : "s"}{((node.data.listeningCount as number) || 0) > 0 ? ` · ${String(node.data.listeningCount)} listening` : ""}</div>
      </>
    );
  } else if (node.type === "remote") {
    body = (
      <>
        <div className="u-tip-title">{node.label}</div>
        <div className="u-tip-line mono">{String(node.data.ip)}:{String(node.data.port)}</div>
        <div className="u-tip-line">{node.data.hostname && node.data.hostname !== "UNRESOLVED" ? String(node.data.hostname) : "External endpoint"}</div>
      </>
    );
  } else if (node.type === "port") {
    body = (
      <>
        <div className="u-tip-title">{String(node.data.protocol)} :{String(node.data.port)}</div>
        <div className="u-tip-line mono">{String(node.data.localAddress)}</div>
        <div className="u-tip-line">{node.listening ? "Listening socket" : "Open endpoint"}</div>
      </>
    );
  } else if (node.type === "laptop") {
    body = (
      <>
        <div className="u-tip-title">{node.label}</div>
        <div className="u-tip-line mono">{`${node.data.localIp || "—"} · ${node.connections} conns`}</div>
      </>
    );
  } else {
    body = (
      <>
        <div className="u-tip-title">{node.label}</div>
        <div className="u-tip-line">{node.detail}</div>
      </>
    );
  }
  return (
    <Html position={[0, 0.42, 0]} center zIndexRange={[40, 0]} style={{ pointerEvents: "none" }} wrapperClass="u-tip-wrap">
      <div className="u-tip-card">{body}</div>
    </Html>
  );
}

/* ================================================================== */
/* SELECTION — related-graph dimming (2-hop relationships)             */
/* ================================================================== */

function useSelection(model: UniverseModel, selectedNodeId: string | null) {
  return useMemo(() => {
    const related = new Set<string>();
    const relationLinks = new Set<string>();
    if (selectedNodeId) {
      related.add(selectedNodeId);
      let frontier = new Set([selectedNodeId]);
      for (let depth = 0; depth < 2; depth++) {
        const next = new Set<string>();
        for (const n of frontier) {
          for (const l of model.links) {
            if (l.from === n && !related.has(l.to)) {
              next.add(l.to);
              related.add(l.to);
            } else if (l.to === n && !related.has(l.from)) {
              next.add(l.from);
              related.add(l.from);
            }
            if (l.from === n || l.to === n) relationLinks.add(l.id);
          }
        }
        frontier = next;
      }
    }
    const nodeDim = (id: string) => {
      if (!selectedNodeId) return 1;
      if (id === selectedNodeId) return 1.22;
      return related.has(id) ? 1 : 0.3;
    };
    const linkDim = (id: string, from: string, to: string) => {
      if (!selectedNodeId) return 1;
      if (relationLinks.has(id)) return 1;
      if (related.has(from) || related.has(to)) return 0.85;
      return 0.16;
    };
    return { related, relationLinks, nodeDim, linkDim };
  }, [model, selectedNodeId]);
}

/* ================================================================== */
/* PREFERS REDUCED MOTION                                              */
/* ================================================================== */

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(mq.matches);
    const onChange = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return reduced;
}

/* ================================================================== */
/* SCENE ENVIRONMENT                                                   */
/* ================================================================== */

function GroundShadow({ node }: { node: UniverseNode }) {
  const r = nodeRadius(node.type);
  return (
    <mesh position={[0, -3.3 - node.y + 0.012, 0]} rotation={[-Math.PI / 2, 0, 0]}>
      <circleGeometry args={[r * 0.9, 24]} />
      <meshBasicMaterial color="#02060c" transparent opacity={0.4} depthWrite={false} />
    </mesh>
  );
}

function Lights() {
  return (
    <>
      <ambientLight intensity={0.34} />
      <hemisphereLight args={["#4a5a72", "#060a10", 0.5]} />
      <directionalLight position={[-7, 9, 6]} intensity={0.8} color="#d0e0f0" />
      <pointLight position={[0, 1.4, 3]} intensity={1.2} color={C.cyan} distance={16} decay={2} />
      <pointLight position={[-9, 7, -8]} intensity={0.7} color={C.purple} distance={26} decay={2} />
      <pointLight position={[10, 9, 4]} intensity={0.5} color="#3a5bd0" distance={28} decay={2} />
      <pointLight position={[0, 5, -4]} intensity={0.5} color={C.amber} distance={14} decay={2} />
    </>
  );
}

function DustField() {
  const shared = useSceneShared();
  const points = useMemo(() => {
    const count = 96;
    const pos = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const r = 7 + Math.random() * 14;
      const a = Math.random() * Math.PI * 2;
      const e = Math.random() * Math.PI * 0.8;
      pos[i * 3] = Math.cos(a) * Math.cos(e) * r;
      pos[i * 3 + 1] = Math.sin(e) * r * 0.55 + 2;
      pos[i * 3 + 2] = Math.sin(a) * Math.cos(e) * r;
    }
    return pos;
  }, []);
  const ref = useRef<THREE.Points>(null);
  useFrame((_, delta) => {
    if (!ref.current) return;
    ref.current.visible = shared.qualityRef.current !== "low";
    if (!shared.paused && !shared.reducedMotion) ref.current.rotation.y += Math.min(delta, 0.05) * 0.004;
  });
  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[points, 3]} />
      </bufferGeometry>
      <pointsMaterial color="#2a3a4f" size={0.035} transparent opacity={0.2} sizeAttenuation depthWrite={false} />
    </points>
  );
}

const atmosFront = (() => {
  const S = 512;
  const c = document.createElement("canvas");
  c.width = S;
  c.height = S;
  const ctx = c.getContext("2d")!;
  const g = ctx.createLinearGradient(0, 0, 0, S);
  g.addColorStop(0, "rgba(30,44,70,0)");
  g.addColorStop(0.5, "rgba(20,34,56,0.20)");
  g.addColorStop(1, "rgba(30,44,70,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, S, S);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
})();

const floorTexture = (() => {
  const S = 256;
  const c = document.createElement("canvas");
  c.width = S;
  c.height = S;
  const ctx = c.getContext("2d")!;
  const g = ctx.createRadialGradient(S / 2, S / 2, 8, S / 2, S / 2, S / 2);
  g.addColorStop(0, "rgba(24,42,66,0.5)");
  g.addColorStop(0.45, "rgba(10,20,34,0.22)");
  g.addColorStop(1, "rgba(3,6,12,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, S, S);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
})();

function SceneEnvironment() {
  return (
    <>
      {/* far atmosphere layers for genuine depth */}
      <mesh position={[0, 6, -34]} scale={[1, 1, 1]}>
        <planeGeometry args={[120, 70]} />
        <meshBasicMaterial map={atmosFront} transparent opacity={0.5} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh position={[0, -8, -6]} rotation={[0.4, 0, 0]} scale={[1, 1, 1]}>
        <planeGeometry args={[120, 50]} />
        <meshBasicMaterial map={atmosFront} transparent opacity={0.35} depthWrite={false} toneMapped={false} />
      </mesh>
      {/* horizon ring far away */}
      <mesh position={[0, 0.5, -13]} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[17, 0.02, 6, 90]} />
        <meshBasicMaterial color={C.cyanDeep} transparent opacity={0.12} depthWrite={false} toneMapped={false} />
      </mesh>
      <Grid position={[0, -3.35, 0]} args={[20, 20]} cellSize={0.5} cellThickness={0.4} cellColor={C.gridLine} sectionSize={2.5} sectionThickness={0.8} sectionColor={C.gridSection} fadeDistance={42} fadeStrength={2.6} infiniteGrid followCamera={false} />
      <mesh position={[0, -3.32, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[80, 80]} />
        <meshBasicMaterial color={C.floor} />
      </mesh>
      <mesh position={[0, -3.315, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <circleGeometry args={[26, 48]} />
        <meshBasicMaterial map={floorTexture} transparent opacity={0.7} depthWrite={false} toneMapped={false} />
      </mesh>
    </>
  );
}

/* ================================================================== */
/* CAMERA SYSTEM — cinematic, eased, no teleporting                    */
/* ================================================================== */

type CameraApi = {
  reset: () => void;
  fitAll: () => void;
  focusSelection: () => void;
};

function CameraRig({ mode, selectedNodeId, model, apiRef }: {
  mode: CameraMode;
  selectedNodeId: string | null;
  model: UniverseModel;
  apiRef: { current: CameraApi | null };
}) {
  const { camera } = useThree();
  const controlsRef = useRef<any>(null);
  const sph = useRef(new THREE.Spherical());
  const goal = useRef({ pos: new THREE.Vector3(9, 6, 11.5), target: new THREE.Vector3(0, 1.6, -1) });
  const followRef = useRef(false);
  const overrideRef = useRef(false);
  const prevSelected = useRef<string | null>(null);
  const shared = useSceneShared();
  const targetV = useRef(new THREE.Vector3());

  const preset = useCallback((m: CameraMode) => {
    overrideRef.current = false;
    goal.current.target.set(0, 1.4, -1);
    if (m === "top") {
      goal.current.pos.set(0, 26, 0.5);
      goal.current.target.set(0, 0.5, -1);
    } else if (m === "2d") {
      goal.current.pos.set(0, 2.2, 27);
      goal.current.target.set(0, 1.4, -2);
    } else {
      goal.current.pos.set(9, 6, 11.5);
      goal.current.target.set(0, 1.4, -1);
    }
  }, []);

  const frame = useCallback((center: THREE.Vector3, nodes: UniverseNode[], close = 1) => {
    const bbox = new THREE.Box3();
    if (!nodes.length) bbox.setFromCenterAndSize(center, new THREE.Vector3(2, 2, 2));
    else {
      for (const n of nodes) bbox.expandByPoint(new THREE.Vector3(n.x, n.y, n.z));
      bbox.expandByPoint(center);
    }
    const size = new THREE.Vector3();
    bbox.getSize(size);
    const radius = Math.max(size.length() / 2, 2.2);
    const dir = new THREE.Vector3(1, 0.62, 1.1).normalize();
    const dist = Math.max((radius * 2.15 + 2.4) / close, 2);
    goal.current.pos.copy(center).addScaledVector(dir, dist);
    goal.current.target.copy(center);
  }, []);

  useEffect(() => {
    preset(mode);
  }, [mode, preset]);

  useEffect(() => {
    if (selectedNodeId === prevSelected.current) return;
    prevSelected.current = selectedNodeId;
    if (!selectedNodeId) {
      followRef.current = false;
      overrideRef.current = false;
      preset(mode);
      return;
    }
    overrideRef.current = false;
    const node = model.nodes.find((n) => n.id === selectedNodeId);
    if (!node) return;
    const center = new THREE.Vector3(node.x, node.y, node.z);
    const relatedNodes = model.links
      .filter((l) => l.from === selectedNodeId || l.to === selectedNodeId)
      .map((l) => model.nodes.find((n) => n.id === (l.from === selectedNodeId ? l.to : l.from)))
      .filter((n): n is UniverseNode => !!n);
    const cluster = [node, ...relatedNodes.slice(0, 14)];
    const close = shared.dblFocus.current === selectedNodeId ? 1.55 : 1.05;
    frame(center, cluster, close);
    if (shared.dblFocus.current === selectedNodeId) shared.dblFocus.current = null;
    followRef.current = node.type === "process" || node.type === "remote";
  }, [selectedNodeId, model.nodes, model.links, frame, preset, mode, shared.dblFocus]);

  useEffect(() => {
    apiRef.current = {
      reset() {
        followRef.current = false;
        overrideRef.current = false;
        preset(mode);
      },
      fitAll() {
        followRef.current = false;
        overrideRef.current = false;
        const nodes = model.nodes;
        const center = new THREE.Vector3();
        for (const n of nodes) center.add(new THREE.Vector3(n.x, n.y, n.z));
        if (nodes.length) center.divideScalar(nodes.length);
        frame(center, nodes, 0.82);
      },
      focusSelection() {
        if (!selectedNodeId) {
          apiRef.current?.fitAll();
          return;
        }
        overrideRef.current = false;
        const node = model.nodes.find((n) => n.id === selectedNodeId);
        if (!node) return;
        const center = new THREE.Vector3(node.x, node.y, node.z);
        const relatedNodes = model.links
          .filter((l) => l.from === selectedNodeId || l.to === selectedNodeId)
          .map((l) => model.nodes.find((n) => n.id === (l.from === selectedNodeId ? l.to : l.from)))
          .filter((n): n is UniverseNode => !!n);
        frame(center, [node, ...relatedNodes.slice(0, 14)], 1.5);
        followRef.current = true;
      },
    };
  }, [apiRef, model.nodes, model.links, frame, preset, mode, selectedNodeId]);

  useFrame((state, delta) => {
    const dt = Math.min(delta, 0.05);
    const lambda = shared.reducedMotion ? 40 : 2.6;
    if (followRef.current && selectedNodeId && !overrideRef.current) {
      const node = model.nodes.find((n) => n.id === selectedNodeId);
      if (node) goal.current.target.set(node.x, node.y, node.z);
    }
    const controls = controlsRef.current;
    const curTarget = targetV.current;
    curTarget.copy(controls ? controls.target : goal.current.target);
    // damp target
    curTarget.x = dampn(curTarget.x, goal.current.target.x, lambda * 1.2, dt);
    curTarget.y = dampn(curTarget.y, goal.current.target.y, lambda * 1.2, dt);
    curTarget.z = dampn(curTarget.z, goal.current.target.z, lambda * 1.2, dt);
    // spherical damp: current offset about current target vs goal offset
    sph.current.setFromVector3(camera.position.clone().sub(curTarget));
    const goalRel = _v1.copy(goal.current.pos).sub(goal.current.target);
    const gs = new THREE.Spherical().setFromVector3(goalRel);
    sph.current.radius = dampn(sph.current.radius, gs.radius, lambda, dt);
    sph.current.phi = dampn(sph.current.phi, gs.phi, lambda, dt);
    sph.current.theta = dampAngle(sph.current.theta, gs.theta, lambda, dt);
    camera.position.copy(curTarget).add(_v2.setFromSpherical(sph.current));
    if (controls) {
      controls.target.copy(curTarget);
    }
    void state;
  });

  return (
    <OrbitControls
      ref={controlsRef}
      enableDamping
      dampingFactor={0.09}
      minDistance={1.9}
      maxDistance={60}
      enablePan
      panSpeed={0.7}
      rotateSpeed={0.42}
      maxPolarAngle={mode === "top" ? 0.34 : Math.PI}
      enableRotate={mode !== "2d"}
      onStart={() => {
        if (followRef.current) overrideRef.current = true;
      }}
    />
  );
}

/* ================================================================== */
/* SMOOTH POSITION + SPAWN lifecycle                                   */
/* ================================================================== */

function SmoothPos({ node, hover, selected, children }: {
  node: UniverseNode;
  hover: boolean;
  selected: boolean;
  children: React.ReactNode;
}) {
  const groupRef = useRef<THREE.Group>(null);
  const shared = useSceneShared();
  const paused = shared.paused;
  const reduced = shared.reducedMotion;
  const scaleRef = useRef(0.0001);
  const bornAt = useRef<number | null>(null);

  useFrame((state, delta) => {
    const dt = Math.min(delta, 0.05);
    const g = groupRef.current;
    if (!g) return;
    if (bornAt.current == null) bornAt.current = state.clock.elapsedTime;
    if (!paused) {
      const k = reduced ? 60 : 3.2;
      g.position.x = THREE.MathUtils.damp(g.position.x, node.x, k, dt);
      g.position.y = THREE.MathUtils.damp(g.position.y, node.y, k, dt);
      g.position.z = THREE.MathUtils.damp(g.position.z, node.z, k, dt);
      const target = (hover ? 1.06 : 1) * (selected ? 1.1 : 1);
      const bloom = reduced ? 1 : 1 + 0.14 * Math.exp(-(state.clock.elapsedTime - bornAt.current) * 2.2);
      scaleRef.current = THREE.MathUtils.damp(scaleRef.current, target * bloom, reduced ? 60 : 3.6, dt);
      g.scale.setScalar(Math.max(0.0001, scaleRef.current));
    }
  });
  return (
    <group ref={groupRef} position={[node.x, node.y, node.z]} scale={0.0001}>
      {children}
    </group>
  );
}

/* ================================================================== */
/* SCENE                                                               */
/* ================================================================== */

type LinkRender = { link: UniverseLink; anim: LinkAnim; ghost: boolean };

function Scene({ model, events, portEvents, selectedNodeId, onSelectNode, onSelectLink, cameraMode, paused, camApiRef }: {
  model: UniverseModel;
  events: TopologyConnectionEvent[];
  portEvents: PortEvent[];
  selectedNodeId: string | null;
  onSelectNode: (node: UniverseNode | null) => void;
  onSelectLink?: (link: UniverseLink | null) => void;
  cameraMode: CameraMode;
  paused: boolean;
  camApiRef: { current: CameraApi | null };
}) {
  const linkStore = useRef(new Map<string, LinkAnim>());
  const packetStore = useRef(new Map<string, PacketBind>());
  const qualityRef = useRef<QualityLevel>("high");
  const dblFocus = useRef<string | null>(null);
  const pulseMap = useRef(new Map<string, number>());
  const [linkRenders, setLinkRenders] = useState<LinkRender[]>([]);
  const [ghostLinks, setGhostLinks] = useState<LinkRender[]>([]);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const [ghostNodes, setGhostNodes] = useState<UniverseNode[]>([]);
  const prevNodesRef = useRef<UniverseNode[]>([]);
  const nodeMap = useMemo(() => new Map(model.nodes.map((n) => [n.id, n] as const)), [model.nodes]);
  const reducedMotion = usePrefersReducedMotion();
  const frameStats = useRef({ frames: 0, acc: 0 });
  const lastHandled = useRef(0);
  const timeRef = useRef(0);
  sharedQuality.level = qualityRef.current;

  /* ---- link store diff (incremental, stable IDs, object reuse) ---- */
  useEffect(() => {
    const store = linkStore.current;
    const currentIds = new Set<string>();
    for (const link of model.links) {
      currentIds.add(link.id);
      let a = store.get(link.id);
      const fromNode = nodeMap.get(link.from);
      const toNode = nodeMap.get(link.to);
      const f: [number, number, number] = fromNode ? [fromNode.x, fromNode.y, fromNode.z] : [0, 0, 0];
      const t: [number, number, number] = toNode ? [toNode.x, toNode.y, toNode.z] : [0, 0, 0];
      if (!a) {
        a = makeLinkAnim(link, f, t);
        store.set(link.id, a);
      } else {
        a.link = link;
        a.dying = false;
        if (a.phase === "close" && a.phaseT > 0.9) {
          a.phase = "idle";
          a.phaseT = 0;
        }
      }
    }
    for (const [id, a] of store) {
      if (currentIds.has(id)) continue;
      if (!a.dying) {
        a.dying = true;
        a.phase = "close";
        a.phaseT = 0;
      }
    }
    const live: LinkRender[] = [];
    const ghosts: LinkRender[] = [];
    for (const [id, a] of store) {
      if (a.dying && !currentIds.has(id)) ghosts.push({ link: a.link, anim: a, ghost: true });
      else if (currentIds.has(id)) live.push({ link: a.link, anim: a, ghost: false });
    }
    setLinkRenders(live);
    setGhostLinks(ghosts);
  }, [model.links, nodeMap]);

  /* ---- ghost nodes (graceful despawn, no popping) ---- */
  useEffect(() => {
    const prev = prevNodesRef.current;
    const currentIds = new Set(model.nodes.map((n) => n.id));
    const gone = prev.filter((n) => !currentIds.has(n.id));
    prevNodesRef.current = model.nodes;
    if (!gone.length) return;
    setGhostNodes((existing) => {
      const keep = existing.filter((g) => !currentIds.has(g.id));
      const fresh = gone.filter((g) => !existing.some((eg) => eg.id === g.id));
      return [...fresh, ...keep].slice(0, 8);
    });
  }, [model.nodes]);

  /* ---- connection events → directional pulse + link phase ---- */
  useEffect(() => {
    const store = linkStore.current;
    const byConnKey = new Map<string, LinkAnim>();
    const byRemote = new Map<string, LinkAnim>();
    for (const a of store.values()) {
      if (a.link.edge === "remote") {
        if (a.link.connectionKey) byConnKey.set(a.link.connectionKey, a);
        byRemote.set(`${a.link.remotePort ?? 0}`, a);
      }
    }
    let idx = 0;
    for (const ev of events) {
      if (!ev || typeof ev !== "object") continue;
      const t = ev.event_type;
      const key = connKey(ev.local_addr, ev.local_port, ev.remote_addr, ev.remote_port, ev.protocol);
      const srcId = ev.pid ? `proc-${ev.pid}` : "laptop";
      const dstId = ev.remote_addr ? `remote-${ev.remote_addr}-${ev.remote_port ?? 0}` : "";
      const procLink = ev.pid ? store.get(`laptop-proc-${ev.pid}`) : undefined;
      const match = (): LinkAnim | undefined =>
        store.get(key) || byConnKey.get(key) || byRemote.get(`${ev.remote_port ?? 0}`) || procLink;
      if (t === "NEW") {
        const a = match();
        if (a) {
          a.phase = "form";
          a.phaseT = 0;
          a.burst = 1;
        }
        if (srcId && nodeMap.has(srcId)) ping(srcId, pulseMap);
        if (dstId && nodeMap.has(dstId)) ping(dstId, pulseMap);
      } else if (t === "CLOSED") {
        const a = match();
        if (a && !a.dying) {
          a.phase = "close";
          a.phaseT = 0;
          a.burst = 0;
        }
        if (srcId && nodeMap.has(srcId)) ping(srcId, pulseMap);
      } else if (t === "STATE_CHANGE") {
        const a = match();
        if (a) {
          a.phase = ev.state === "ESTABLISHED" ? "form" : "idle";
          a.burst = ev.state === "ESTABLISHED" ? 0.7 : 0;
          if (srcId && nodeMap.has(srcId)) ping(srcId, pulseMap);
        }
      }
      idx++;
    }
    if (idx !== lastHandled.current) lastHandled.current = idx;
  }, [events, nodeMap]);

  /* ---- port events → socket lifecycle ---- */
  useEffect(() => {
    for (const pe of portEvents) {
      if (!pe || typeof pe !== "object") continue;
      const proto = (pe.protocol || "TCP").toUpperCase();
      const localAddr = pe.local_addr || "0.0.0.0";
      const pid = pe.pid ?? 0;
      const pkey = `port-${proto}-${localAddr}-${pe.local_port}-${pid}`;
      if (pe.event_type === "PORT_OPENED") {
        const store = linkStore.current;
        for (const a of store.values()) {
          if (a.link.edge === "port" && a.link.localPort === pe.local_port && (a.link.protocol || "TCP").toUpperCase() === proto) {
            a.phase = "form";
            a.phaseT = 0;
            a.burst = 0.75;
          }
        }
        if (nodeMap.has(pkey)) ping(pkey, pulseMap);
        if (pid && nodeMap.has(`proc-${pid}`)) ping(`proc-${pid}`, pulseMap);
      } else if (pe.event_type === "PORT_CLOSED") {
        const store = linkStore.current;
        for (const a of store.values()) {
          if (a.link.edge === "port" && a.link.localPort === pe.local_port && (a.link.protocol || "TCP").toUpperCase() === proto && !a.dying) {
            a.phase = "close";
            a.phaseT = 0;
          }
        }
        if (nodeMap.has(pkey)) ping(pkey, pulseMap);
      }
    }
  }, [portEvents, nodeMap]);

  /* ---- adaptive quality governor ---- */
  useFrame((state, delta) => {
    timeRef.current += delta;
    const fs = frameStats.current;
    fs.frames++;
    fs.acc += Math.min(delta, 0.05);
    if (fs.frames >= 45) {
      const avg = fs.acc / fs.frames;
      if (avg > 0.024) {
        if (qualityRef.current !== "low") {
          qualityRef.current = "low";
          state.gl.setPixelRatio(1);
        }
      } else if (avg > 0.017) {
        if (qualityRef.current === "low") {
          qualityRef.current = "medium";
          state.gl.setPixelRatio(1.35);
        }
      } else if (qualityRef.current !== "high") {
        qualityRef.current = "high";
        state.gl.setPixelRatio(Math.min(1.75, state.gl.getPixelRatio() || 1.75));
      }
      sharedQuality.level = qualityRef.current;
      fs.frames = 0;
      fs.acc = 0;
    }
  });

  const removeGhost = useCallback((id: string) => {
    const store = linkStore.current;
    const a = store.get(id);
    if (a && a.dying) {
      if (a.geometry) {
        a.geometry.dispose();
        a.geometry = null;
      }
      a.curve = null;
      store.delete(id);
    }
    setGhostLinks((prev) => prev.filter((r) => r.link.id !== id));
  }, []);

  const removeGhostNode = useCallback((id: string) => {
    setGhostNodes((prev) => prev.filter((n) => n.id !== id));
  }, []);

  const { nodeDim, linkDim } = useSelection(model, selectedNodeId);

  const selectNode = useCallback((node: UniverseNode) => {
    onSelectNode(node);
  }, [onSelectNode]);

  const selectLink = useCallback((link: UniverseLink) => {
    if (onSelectLink) onSelectLink(link);
    onSelectNode(nodeMap.get(link.to) || null);
  }, [onSelectLink, onSelectNode, nodeMap]);

  const selectNodeAndFocus = useCallback((node: UniverseNode) => {
    dblFocus.current = node.id;
    onSelectNode(node);
  }, [onSelectNode]);

  const flowBoost = clamp((model.stats.uploadRate + model.stats.downloadRate) / 600000, 0, 2.6);

  const labelNodes = useMemo(() => {
    const picked = model.nodes.filter((n) =>
      n.type === "laptop" ||
      n.type === "gateway" ||
      n.type === "internet" ||
      n.type === "dns" ||
      (n.type === "process" && n.weight >= 0.7) ||
      (n.type === "remote" && (n.secState !== "normal" || (n.data.hostname && n.data.hostname !== "UNRESOLVED"))) ||
      (n.type === "adapter" && n.weight >= 0.85) ||
      (n.type === "neighbor" && false) ||
      (n.type === "port" && n.listening)
    );
    const ids = new Set(picked.map((n) => n.id));
    if (hoverId && !ids.has(hoverId)) {
      const h = model.nodes.find((n) => n.id === hoverId);
      if (h) picked.push(h);
    }
    if (selectedNodeId && !ids.has(selectedNodeId)) {
      const s = model.nodes.find((n) => n.id === selectedNodeId);
      if (s) picked.push(s);
    }
    return picked;
  }, [model.nodes, hoverId, selectedNodeId]);

  return (
    <SceneSharedCtx.Provider value={{ paused, reducedMotion, qualityRef, linkStore, packetStore, dblFocus, hoverId, setHoverId, pulseMap }}>
      <EventPulseDriver />
      <Lights />
      <SceneEnvironment />
      <DustField />
      <PacketLayer flowBoost={flowBoost} />
      {linkRenders.map((r) => (
        <LinkTube
          key={r.link.id}
          link={r.link}
          anim={r.anim}
          dim={linkDim(r.link.id, r.link.from, r.link.to)}
          selected={selectedNodeId === r.link.id}
          modelNodes={model.nodes}
          flowBoost={flowBoost}
          onClick={() => selectLink(r.link)}
        />
      ))}
      {ghostLinks.map((r) => (
        <GhostLink key={`ghost-${r.link.id}`} anim={r.anim} dim={0.35} onDone={() => removeGhost(r.link.id)} />
      ))}
      {model.nodes.map((node) => (
        <SmoothPos key={node.id} node={node} hover={hoverId === node.id} selected={selectedNodeId === node.id}>
          <NodeView
            node={node}
            dim={nodeDim(node.id)}
            selected={selectedNodeId === node.id}
            hovered={hoverId === node.id}
            onSelect={() => selectNode(node)}
            onHover={(h) => setHoverId(h ? node.id : null)}
          />
          {nodeDim(node.id) >= 0.75 && node.weight >= 0.45 && <GroundShadow node={node} />}
          {hoverId === node.id && <TooltipHost node={node} />}
        </SmoothPos>
      ))}
      {ghostNodes.map((node) => (
        <GhostNodeView key={`gn-${node.id}`} node={node} onDone={() => removeGhostNode(node.id)} />
      ))}
      {labelNodes.map((node) => (
        <NodeLabel key={node.id} node={node} hovered={hoverId === node.id} selected={selectedNodeId === node.id} />
      ))}
      <CameraRig mode={cameraMode} selectedNodeId={selectedNodeId} model={model} apiRef={camApiRef} />
    </SceneSharedCtx.Provider>
  );
}

/* ================================================================== */
/* MAIN EXPORT                                                         */
/* ================================================================== */

export { buildUniverseModel, defaultStats };

export function NetworkUniverse3D({ data, ports, events, portEvents, isLive, mode, selectedNodeId, onSelectNode, onSelectLink, cameraMode, paused }: {
  data: NetworkTopologyData | null;
  ports?: PortIntelligenceData | null;
  events?: TopologyConnectionEvent[];
  portEvents?: PortEvent[];
  isLive: boolean;
  mode?: NetworkMode;
  selectedNodeId: string | null;
  onSelectNode: (node: UniverseNode | null) => void;
  onSelectLink?: (link: UniverseLink | null) => void;
  cameraMode: CameraMode;
  paused: boolean;
}) {
  const model = useMemo(() => buildUniverseModel(data, ports ?? null), [data, ports]);
  const resolvedMode: NetworkMode = mode ?? (isLive ? "live" : "offline");
  const camApiRef = useRef<CameraApi | null>(null);
  const [flashMsg, setFlashMsg] = useState<string | null>(null);
  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const draggedRef = useRef(false);

  const flash = useCallback((msg: string) => {
    setFlashMsg(msg);
    if (flashTimer.current) clearTimeout(flashTimer.current);
    flashTimer.current = setTimeout(() => setFlashMsg(null), 2200);
  }, []);
  useEffect(() => () => {
    if (flashTimer.current) clearTimeout(flashTimer.current);
  }, []);

  return (
    <div
      className="universe-3d-container"
      data-testid="network-universe-3d"
      onPointerDown={() => {
        draggedRef.current = false;
      }}
      onPointerMove={(e) => {
        if (e.buttons > 0) draggedRef.current = true;
      }}
    >
      <Canvas
        camera={{ position: [9, 6, 11.5], fov: 46, near: 0.1, far: 240 }}
        dpr={[1, 1.75]}
        style={{ background: "transparent" }}
        gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
        onPointerMissed={() => {
          if (!draggedRef.current) onSelectNode(null);
          draggedRef.current = false;
        }}
      >
        <fog attach="fog" args={["#05080e", 16, 66]} />
        <Scene
          model={model}
          events={events ?? []}
          portEvents={portEvents ?? []}
          selectedNodeId={selectedNodeId}
          onSelectNode={onSelectNode}
          onSelectLink={onSelectLink}
          cameraMode={cameraMode}
          paused={paused}
          camApiRef={camApiRef}
        />
      </Canvas>

      <div className="universe-overlay-top">
        <div className={`universe-status-badge ${resolvedMode}`}>
          {resolvedMode === "live" ? "● LIVE" : resolvedMode === "simulated" ? "⚡ SIMULATION" : "○ OFFLINE"}
        </div>
        {resolvedMode === "simulated" && (
          <div className="universe-sim-note">SIMULATED PREVIEW — locally generated; switches to real telemetry when the ARGUS engine connects.</div>
        )}
        <div className="universe-stat-row">
          <span>{model.stats.establishedCount} ESTAB</span>
          <span>·</span>
          <span>{model.stats.processes} PROCS</span>
          <span>·</span>
          <span>{model.stats.connections} CONNS</span>
          <span>·</span>
          <span>{model.stats.ports} PORTS</span>
          {model.stats.dnsServers > 0 && (
            <>
              <span>·</span>
              <span>{model.stats.dnsServers} DNS</span>
            </>
          )}
        </div>
        {paused && (
          <div className="universe-status-badge" style={{ color: "hsl(var(--chart-3))", borderColor: "hsl(var(--chart-3)/.5)" }}>
            ⏸ PAUSED
          </div>
        )}
      </div>

      {(model.stats.uploadRate > 0 || model.stats.downloadRate > 0) && (
        <div className="universe-overlay-traffic">
          <span className="universe-traffic-down">↓ {fmtRate(model.stats.downloadRate)}</span>
          <span className="universe-traffic-up">↑ {fmtRate(model.stats.uploadRate)}</span>
        </div>
      )}

      <div className="universe-cam-controls">
        <button type="button" className="universe-cam-btn" onClick={() => {
          camApiRef.current?.reset();
          flash("Camera reset");
        }} title="Reset camera">
          ⌂ Reset
        </button>
        <button type="button" className="universe-cam-btn" onClick={() => {
          camApiRef.current?.fitAll();
          flash("Framing the whole network");
        }} title="Fit all entities">
          ⤢ Fit
        </button>
        <button type="button" className="universe-cam-btn" onClick={() => {
          if (selectedNodeId) {
            camApiRef.current?.focusSelection();
            flash("Focusing selection");
          } else {
            camApiRef.current?.fitAll();
            flash("Select an entity to focus — framed network");
          }
        }} title="Focus selected entity">
          ◎ Focus
        </button>
      </div>

      <div className="universe-legend">
        {[
          { g: C.cyan, label: "Endpoint" },
          { g: C.cyan, label: "Adapter" },
          { g: C.green, label: "App" },
          { g: C.cyanDeep, label: "Port" },
          { g: C.purpleSoft, label: "Remote" },
          { g: C.purple, label: "External" },
          { g: C.blue, label: "Gateway" },
        ].map(({ g, label }) => (
          <span key={label} style={{ color: g }}>
            <i style={{ background: g }} />
            {label}
          </span>
        ))}
        <span style={{ color: C.cyan }}>
          <i style={{ background: C.cyan }} />
          Flow
        </span>
      </div>

      <div className="universe-hint">
        {cameraMode === "3d"
          ? "Drag to orbit · scroll to zoom · click an entity to inspect · double-click to focus"
          : cameraMode === "2d"
            ? "Flat relationship view · pan + zoom · click an entity to inspect"
            : "Topology layout from above · click an entity to inspect"}
      </div>

      {flashMsg && <div className="universe-flash">{flashMsg}</div>}
    </div>
  );
}