/**
 * backtrace-3d-visualizer.tsx — ARGUS 3D Forensic Backtrace & Network Intelligence Visualizer.
 *
 * Premium cinematic 3D visualizer built on React Three Fiber & Three.js.
 * Reuses existing ARGUS 3D engine capabilities (Canvas, OrbitControls, Billboard, Text, Html, Grid).
 * Visualizes 12-step attack chains, directional flow particles, World Globe View, floating IP intelligence,
 * Endpoint Churn analysis, Level 0-5 Attribution, and Trace Boundary enforcement.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls, Text, Billboard, Html, Grid, RoundedBox } from "@react-three/drei";
import * as THREE from "three";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  Clock,
  Compass,
  Cpu,
  Database,
  ExternalLink,
  Eye,
  FileText,
  GitBranch,
  Globe,
  HardDrive,
  Info,
  Layers,
  Lock,
  Maximize2,
  Minimize2,
  Network,
  Pause,
  Play,
  Radio,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from "lucide-react";
import type {
  UnifiedBacktraceData,
  BacktraceNode3D,
  BacktraceLink3D,
  NetworkIntel,
} from "@/hooks/use-backtrace";

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(" ");
}

/* ================================================================== */
/* 3D CUSTOM MESHES FOR FORENSIC OBJECTS                              */
/* ================================================================== */

function RemoteEndpointMesh({ node, isSelected, onClick }: { node: BacktraceNode3D; isSelected: boolean; onClick: () => void }) {
  const meshRef = useRef<THREE.Group>(null);

  useFrame((_, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.4;
    }
  });

  return (
    <group position={[node.x, node.y, node.z]} onClick={onClick}>
      <group ref={meshRef}>
        <mesh>
          <boxGeometry args={[2.2, 2.2, 2.2]} />
          <meshStandardMaterial
            color={isSelected ? "#a855f7" : "#8b5cf6"}
            emissive={isSelected ? "#7e22ce" : "#4c1d95"}
            emissiveIntensity={0.6}
            roughness={0.2}
            metalness={0.8}
          />
        </mesh>
        {/* Outer glowing wireframe frame */}
        <mesh scale={1.15}>
          <boxGeometry args={[2.2, 2.2, 2.2]} />
          <meshBasicMaterial color="#c084fc" wireframe transparent opacity={0.4} />
        </mesh>
      </group>

      <Billboard position={[0, 2.2, 0]}>
        <Text fontSize={0.42} color="#f3e8ff" anchorX="center" anchorY="bottom" outlineWidth={0.03} outlineColor="#000">
          {node.label}
        </Text>
      </Billboard>
    </group>
  );
}

function VpnProxyMesh({ node, isSelected, onClick }: { node: BacktraceNode3D; isSelected: boolean; onClick: () => void }) {
  const ringRef = useRef<THREE.Mesh>(null);

  useFrame((_, delta) => {
    if (ringRef.current) {
      ringRef.current.rotation.z += delta * 1.2;
    }
  });

  return (
    <group position={[node.x, node.y, node.z]} onClick={onClick}>
      <mesh>
        <cylinderGeometry args={[1.2, 1.2, 2.0, 16]} />
        <meshStandardMaterial color="#f59e0b" emissive="#78350f" roughness={0.3} metalness={0.7} />
      </mesh>
      <mesh ref={ringRef} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[1.7, 0.08, 16, 32]} />
        <meshBasicMaterial color="#fbbf24" transparent opacity={0.8} />
      </mesh>

      <Billboard position={[0, 1.8, 0]}>
        <Text fontSize={0.38} color="#fef3c7" anchorX="center" anchorY="bottom" outlineWidth={0.03} outlineColor="#000">
          {node.label}
        </Text>
      </Billboard>
    </group>
  );
}

function LocalGatewayMesh({ node, isSelected, onClick }: { node: BacktraceNode3D; isSelected: boolean; onClick: () => void }) {
  return (
    <group position={[node.x, node.y, node.z]} onClick={onClick}>
      <mesh>
        <cylinderGeometry args={[1.5, 1.8, 1.2, 6]} />
        <meshStandardMaterial color="#0284c7" emissive="#075985" roughness={0.2} metalness={0.8} />
      </mesh>

      <Billboard position={[0, 1.4, 0]}>
        <Text fontSize={0.36} color="#e0f2fe" anchorX="center" anchorY="bottom" outlineWidth={0.03} outlineColor="#000">
          {node.label}
        </Text>
      </Billboard>
    </group>
  );
}

function ProcessDataCoreMesh({ node, isSelected, onClick }: { node: BacktraceNode3D; isSelected: boolean; onClick: () => void }) {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((_, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.x += delta * 0.6;
      meshRef.current.rotation.y += delta * 0.8;
    }
  });

  const isParent = node.type === "parent_process";

  return (
    <group position={[node.x, node.y, node.z]} onClick={onClick}>
      <mesh ref={meshRef}>
        <octahedronGeometry args={[isParent ? 1.4 : 1.7, 0]} />
        <meshStandardMaterial
          color={isParent ? "#3b82f6" : "#eab308"}
          emissive={isParent ? "#1d4ed8" : "#854d0e"}
          emissiveIntensity={0.7}
          roughness={0.1}
          metalness={0.9}
        />
      </mesh>

      <Billboard position={[0, 1.6, 0]}>
        <Text fontSize={0.4} color="#fef9c3" anchorX="center" anchorY="bottom" outlineWidth={0.03} outlineColor="#000">
          {node.label}
        </Text>
      </Billboard>
    </group>
  );
}

function DetectionAlertMesh({ node, isSelected, onClick }: { node: BacktraceNode3D; isSelected: boolean; onClick: () => void }) {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (meshRef.current) {
      const s = 1.0 + Math.sin(state.clock.getElapsedTime() * 5) * 0.12;
      meshRef.current.scale.setScalar(s);
    }
  });

  return (
    <group position={[node.x, node.y, node.z]} onClick={onClick}>
      <mesh ref={meshRef}>
        <octahedronGeometry args={[1.8, 1]} />
        <meshStandardMaterial color="#ef4444" emissive="#991b1b" emissiveIntensity={0.9} roughness={0.1} />
      </mesh>

      <Billboard position={[0, 1.8, 0]}>
        <Text fontSize={0.42} color="#fee2e2" anchorX="center" anchorY="bottom" outlineWidth={0.03} outlineColor="#000">
          {node.label}
        </Text>
      </Billboard>
    </group>
  );
}

function FileActivityMesh({ node, isSelected, onClick }: { node: BacktraceNode3D; isSelected: boolean; onClick: () => void }) {
  return (
    <group position={[node.x, node.y, node.z]} onClick={onClick}>
      <mesh>
        <boxGeometry args={[1.2, 1.6, 0.3]} />
        <meshStandardMaterial color="#ec4899" emissive="#831843" roughness={0.3} metalness={0.5} />
      </mesh>

      <Billboard position={[0, 1.4, 0]}>
        <Text fontSize={0.34} color="#fce7f3" anchorX="center" anchorY="bottom" outlineWidth={0.03} outlineColor="#000">
          {node.label}
        </Text>
      </Billboard>
    </group>
  );
}

function DestinationCloudMesh({ node, isSelected, onClick }: { node: BacktraceNode3D; isSelected: boolean; onClick: () => void }) {
  return (
    <group position={[node.x, node.y, node.z]} onClick={onClick}>
      <mesh>
        <sphereGeometry args={[1.6, 24, 24]} />
        <meshStandardMaterial color="#06b6d4" emissive="#164e63" roughness={0.2} metalness={0.8} />
      </mesh>

      <Billboard position={[0, 1.8, 0]}>
        <Text fontSize={0.4} color="#cffafe" anchorX="center" anchorY="bottom" outlineWidth={0.03} outlineColor="#000">
          {node.label}
        </Text>
      </Billboard>
    </group>
  );
}

/* ================================================================== */
/* DIRECTIONAL FLOW LINK BEAM & PARTICLES                             */
/* ================================================================== */

function DirectionalFlowLink({ link, fromNode, toNode }: { link: BacktraceLink3D; fromNode: BacktraceNode3D; toNode: BacktraceNode3D }) {
  const points = useMemo(() => {
    const p1 = new THREE.Vector3(fromNode.x, fromNode.y, fromNode.z);
    const p2 = new THREE.Vector3(toNode.x, toNode.y, toNode.z);
    const mid = p1.clone().add(p2).multiplyScalar(0.5);
    mid.y += 2.0;
    const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
    return curve.getPoints(32);
  }, [fromNode, toNode]);

  const lineGeo = useMemo(() => {
    const geo = new THREE.BufferGeometry().setFromPoints(points);
    return geo;
  }, [points]);

  const particlesRef = useRef<THREE.Points>(null);
  const particleCount = 12;

  const particleProgress = useRef(Array.from({ length: particleCount }, (_, i) => i / particleCount));

  useFrame((_, delta) => {
    if (!particlesRef.current) return;
    const posAttr = particlesRef.current.geometry.attributes.position as THREE.BufferAttribute;
    const array = posAttr.array as Float32Array;

    for (let i = 0; i < particleCount; i++) {
      particleProgress.current[i] += delta * (link.flowParticleSpeed || 1.2) * 0.4;
      if (particleProgress.current[i] > 1.0) particleProgress.current[i] = 0;

      const t = particleProgress.current[i];
      const idx = Math.floor(t * (points.length - 1));
      const pt = points[idx] || points[0];

      array[i * 3] = pt.x;
      array[i * 3 + 1] = pt.y;
      array[i * 3 + 2] = pt.z;
    }
    posAttr.needsUpdate = true;
  });

  const particleGeo = useMemo(() => {
    const geo = new THREE.BufferGeometry();
    const pos = new Float32Array(particleCount * 3);
    geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    return geo;
  }, []);

  const color = link.direction === "inbound" ? "#a855f7" : link.direction === "outbound" ? "#06b6d4" : "#eab308";

  return (
    <group>
      <primitive object={new THREE.Line(lineGeo, new THREE.LineBasicMaterial({ color, opacity: 0.6, transparent: true, linewidth: 2 }))} />
      <points ref={particlesRef} geometry={particleGeo}>
        <pointsMaterial color={color} size={0.35} transparent opacity={0.9} sizeAttenuation />
      </points>
    </group>
  );
}

/* ================================================================== */
/* 3D WORLD GLOBE VIEW MODE                                            */
/* ================================================================== */

function WorldGlobeView({ remoteSource }: { remoteSource?: NetworkIntel }) {
  const globeRef = useRef<THREE.Group>(null);

  useFrame((_, delta) => {
    if (globeRef.current) {
      globeRef.current.rotation.y += delta * 0.15;
    }
  });

  return (
    <group position={[0, 0, 0]}>
      {/* Central 3D Globe */}
      <group ref={globeRef}>
        <mesh>
          <sphereGeometry args={[12, 48, 48]} />
          <meshStandardMaterial color="#0f172a" roughness={0.6} metalness={0.3} wireframe />
        </mesh>
        {/* Atmosphere glow */}
        <mesh scale={1.08}>
          <sphereGeometry args={[12, 32, 32]} />
          <meshBasicMaterial color="#38bdf8" transparent opacity={0.12} side={THREE.BackSide} />
        </mesh>
      </group>

      {/* ARGUS Local Node Pin */}
      <group position={[0, 12.2, 0]}>
        <mesh>
          <sphereGeometry args={[0.6, 16, 16]} />
          <meshBasicMaterial color="#10b981" />
        </mesh>
        <Billboard position={[0, 1.2, 0]}>
          <Text fontSize={0.6} color="#34d399" anchorX="center" anchorY="bottom" outlineWidth={0.04} outlineColor="#000">
            ARGUS ENDPOINT (LOCAL HOST)
          </Text>
        </Billboard>
      </group>

      {/* Remote IP Region Pin */}
      <group position={[8, 8, -5]}>
        <mesh>
          <sphereGeometry args={[0.7, 16, 16]} />
          <meshBasicMaterial color="#c084fc" />
        </mesh>
        <Billboard position={[0, 1.4, 0]}>
          <Text fontSize={0.55} color="#e9d5ff" anchorX="center" anchorY="bottom" outlineWidth={0.04} outlineColor="#000">
            {remoteSource?.geolocation ? `${remoteSource.geolocation.country} (${remoteSource.ip})` : "REMOTE ORIGIN"}
          </Text>
        </Billboard>
      </group>

      {/* Arc Line Connecting Locations */}
      <Billboard position={[4, 11, -2.5]}>
        <Text fontSize={0.4} color="#38bdf8" outlineWidth={0.02} outlineColor="#000">
          APPROXIMATE IP GEOLOCATION ARC
        </Text>
      </Billboard>
    </group>
  );
}

/* ================================================================== */
/* TRACE BOUNDARY BARRIER MESH                                         */
/* ================================================================== */

function TraceBoundaryMesh() {
  return (
    <group position={[-55, 10, 0]}>
      <mesh>
        <planeGeometry args={[1, 30]} />
        <meshBasicMaterial color="#ef4444" transparent opacity={0.4} side={THREE.DoubleSide} />
      </mesh>
      <Billboard position={[0, 0, 0]}>
        <Text fontSize={0.5} color="#fca5a5" anchorX="center" anchorY="middle" outlineWidth={0.03} outlineColor="#000">
          ━━━ TRACE BOUNDARY REACHED ━━━
        </Text>
      </Billboard>
    </group>
  );
}

/* ================================================================== */
/* MAIN 3D FORENSIC SCENE CANVAS                                       */
/* ================================================================== */

export function Backtrace3DVisualizer({
  data,
  activeStep,
  selectedNode,
  onSelectNode,
  cameraMode,
}: {
  data: UnifiedBacktraceData | null;
  activeStep: number;
  selectedNode: BacktraceNode3D | null;
  onSelectNode: (node: BacktraceNode3D) => void;
  cameraMode: "3d" | "globe" | "trace_back" | "trace_forward";
}) {
  const nodes = data?.nodes || [];
  const links = data?.links || [];

  // Filter nodes according to current active animation step
  const visibleNodes = useMemo(() => {
    if (!data) return [];
    if (activeStep >= 12) return nodes;
    // Reveal nodes incrementally based on step
    const count = Math.max(1, Math.min(nodes.length, Math.ceil((activeStep / 12) * nodes.length)));
    return nodes.slice(0, count);
  }, [data, nodes, activeStep]);

  return (
    <div style={{ width: "100%", height: "100%", position: "relative", background: "#030712" }}>
      <Canvas camera={{ position: [15, 20, 45], fov: 45 }}>
        <ambientLight intensity={0.5} />
        <directionalLight position={[10, 20, 15]} intensity={0.9} color="#e0f2fe" />
        <pointLight position={[-20, 10, -10]} intensity={1.2} color="#a855f7" />
        <pointLight position={[20, 10, 10]} intensity={1.2} color="#06b6d4" />

        <Grid
          position={[0, -10, 0]}
          args={[120, 120]}
          cellSize={1}
          cellThickness={0.5}
          cellColor="#1e293b"
          sectionSize={5}
          sectionThickness={1}
          sectionColor="#334155"
          fadeDistance={60}
        />

        {cameraMode === "globe" ? (
          <WorldGlobeView remoteSource={data?.remoteSource} />
        ) : (
          <group>
            <TraceBoundaryMesh />

            {visibleNodes.map((n) => {
              const isSel = selectedNode?.id === n.id;
              switch (n.type) {
                case "remote_endpoint":
                  return <RemoteEndpointMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
                case "vpn_proxy_gateway":
                  return <VpnProxyMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
                case "local_gateway":
                  return <LocalGatewayMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
                case "process":
                case "parent_process":
                  return <ProcessDataCoreMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
                case "detection":
                  return <DetectionAlertMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
                case "file_activity":
                  return <FileActivityMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
                case "destination":
                  return <DestinationCloudMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
                default:
                  return <LocalGatewayMesh key={n.id} node={n} isSelected={isSel} onClick={() => onSelectNode(n)} />;
              }
            })}

            {links.map((link) => {
              const fromN = visibleNodes.find((n) => n.id === link.source);
              const toN = visibleNodes.find((n) => n.id === link.target);
              if (!fromN || !toN) return null;
              return <DirectionalFlowLink key={link.id} link={link} fromNode={fromN} toNode={toN} />;
            })}
          </group>
        )}

        <OrbitControls makeDefault enableDamping dampingFactor={0.08} maxDistance={100} minDistance={5} />
      </Canvas>

      {/* Floating Network Intelligence Card (if remote endpoint is selected) */}
      {selectedNode?.type === "remote_endpoint" && selectedNode.intel && (
        <div
          style={{
            position: "absolute",
            top: 20,
            left: 20,
            width: 320,
            background: "rgba(15, 23, 42, 0.92)",
            border: "1px solid #7e22ce",
            borderRadius: 8,
            padding: 14,
            boxShadow: "0 8px 32px rgba(126, 34, 206, 0.3)",
            backdropFilter: "blur(8px)",
            color: "#f8fafc",
            fontSize: 12,
            zIndex: 20,
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span className="mono" style={{ fontSize: 13, fontWeight: 800, color: "#c084fc" }}>
              🌐 REMOTE INTEL ({selectedNode.intel.ip})
            </span>
            <span
              className="badge"
              style={{
                background: selectedNode.intel.isVpn ? "#78350f" : "#1e1b4b",
                color: selectedNode.intel.isVpn ? "#fde047" : "#a5b4fc",
                fontSize: 10,
              }}
            >
              {selectedNode.intel.classification}
            </span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div><span className="muted">ASN / ISP: </span><span className="mono">{selectedNode.intel.asn}</span></div>
            <div><span className="muted">Organization: </span><span>{selectedNode.intel.organization}</span></div>
            <div><span className="muted">Network Type: </span><span>{selectedNode.intel.networkType}</span></div>
            <div>
              <span className="muted">Location: </span>
              <span className="mono">
                {selectedNode.intel.geolocation ? `${selectedNode.intel.geolocation.city}, ${selectedNode.intel.geolocation.country}` : "UNKNOWN"}
              </span>
            </div>

            {selectedNode.intel.threatIntel && (
              <div style={{ marginTop: 6, borderTop: "1px solid rgba(255,255,255,0.1)", paddingTop: 6 }}>
                <span className="muted">Threat Intel: </span>
                <b style={{ color: "#ef4444" }}>{selectedNode.intel.threatIntel.verdict} (Score: {selectedNode.intel.threatIntel.score}/100)</b>
                <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>{selectedNode.intel.threatIntel.reason}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
