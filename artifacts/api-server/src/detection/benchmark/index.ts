/**
 * Deterministic Baseline Regression & Benchmark Evaluation Engine.
 *
 * Provides reproducible baseline metrics for ARGUS threat detection & attack prediction:
 * - Independent Ground Truth (zero leakage into detection rules)
 * - Quantitative metrics: Precision, Recall, F1, Latency, FP Rate
 * - Attack-stage Prediction Accuracy: Top-1 and Top-3 Hit Rates
 * - Evidence Coverage: proportion of detections supported by valid observed events
 * - Per-rule & Per-scenario breakdown with sample counts
 */

import { DetectionEngine } from "../engine";
import { evaluateNetworkRules } from "../network/rules";
import { evaluateFileRules } from "../file/rules";
import { generatePredictions, type StagePrediction, type AttackStage } from "../../lib/prediction-engine";
import type { SecurityEvent, NetworkViewEvent, FileViewEvent, Detection, DetectionRuleId } from "../types";

export type GroundTruthScenarioCategory =
  | "BENIGN_ACTIVITY"
  | "SUSPICIOUS_BEHAVIOR"
  | "COORDINATED_MULTI_STAGE"
  | "EDGE_CASE_MALFORMED_OUT_OF_ORDER"
  | "AMBIGUOUS_UNKNOWN";

export type ScenarioEvent =
  | { kind: "process"; event: SecurityEvent }
  | { kind: "network"; event: NetworkViewEvent }
  | { kind: "file"; event: FileViewEvent };

export type BenchmarkScenario = {
  id: string;
  name: string;
  category: GroundTruthScenarioCategory;
  description: string;
  simulatedHours: number;
  events: ScenarioEvent[];
  /** Ground truth rule IDs expected to fire for this scenario. Empty array = purely benign scenario. */
  expectedRules: DetectionRuleId[];
  /** Ground truth attack stage sequence expected for this scenario. Empty array = no threat stage. */
  expectedStages: AttackStage[];
};

export type RuleBenchmarkResult = {
  ruleId: string;
  ruleName: string;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  sampleCount: number;
};

export type ScenarioBenchmarkResult = {
  scenarioId: string;
  scenarioName: string;
  category: GroundTruthScenarioCategory;
  simulatedHours: number;
  totalEvents: number;
  expectedRules: DetectionRuleId[];
  firedRules: DetectionRuleId[];
  matchedRules: DetectionRuleId[];
  missedRules: DetectionRuleId[];
  extraRules: DetectionRuleId[];
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositivesPerHour: number;
  avgLatencyMs: number;
  predictionTop1Hit: boolean;
  predictionTop3Hit: boolean;
  evidenceCoverage: number;
  topPredictions: StagePrediction[];
};

export type BenchmarkRunSummary = {
  timestamp: string;
  datasetLabel: "SYNTHETIC_LAB_BENCHMARK_V1";
  isSyntheticDataset: true;
  totalScenarios: number;
  totalEventsProcessed: number;
  totalSimulatedHours: number;
  aggregateMetrics: {
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
    f1Score: number;
    falsePositivesPerHour: number;
    avgLatencyMs: number;
    predictionTop1Accuracy: number;
    predictionTop3Accuracy: number;
    evidenceCoverage: number;
  };
  scenarioResults: ScenarioBenchmarkResult[];
  ruleResults: RuleBenchmarkResult[];
  disclaimer: string;
};

// ---------------------------------------------------------------------------
// Benchmark Scenarios Dataset (Deterministic & Ground-Truth Isolated)
// ---------------------------------------------------------------------------

export const BENCHMARK_SCENARIOS: BenchmarkScenario[] = [
  // 1. Benign Activity: Browser, Document Editing, Dev Tooling, Routine System Work
  {
    id: "scen-benign-01-web-browsing",
    name: "Routine Web Browsing & CDN Downloads",
    category: "BENIGN_ACTIVITY",
    description: "Chrome browser process opening multiple connections to CDN IPs and downloading user files.",
    simulatedHours: 2.0,
    expectedRules: [],
    expectedStages: [],
    events: [
      {
        kind: "process",
        event: {
          id: "evt-b1-1",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T01:00:00.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 4100,
          process_name: "chrome.exe",
          executable_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          command_line: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
          parent_pid: 1200,
          parent_process_name: "explorer.exe",
          username: "BENCH-USER",
        },
      },
      {
        kind: "network",
        event: {
          id: "evt-b1-2",
          type: "NETWORK_CONNECTION",
          origin: "snapshot",
          timestamp: "2026-10-10T01:00:02.000Z",
          source: "windows_network_monitor",
          hostname: "BENCH-HOST",
          pid: 4100,
          process_name: "chrome.exe",
          executable_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          local_addr: "192.168.1.100",
          local_port: 52100,
          remote_addr: "142.250.190.46",
          remote_port: 443,
          remote_role: "REMOTE",
          state: "ESTABLISHED",
        },
      },
    ],
  },
  {
    id: "scen-benign-02-dev-workflow",
    name: "Developer IDE & Package Install Workflow",
    category: "BENIGN_ACTIVITY",
    description: "VS Code running Node.js and downloading packages via curl into installed application folders.",
    simulatedHours: 1.5,
    expectedRules: [],
    expectedStages: [],
    events: [
      {
        kind: "process",
        event: {
          id: "evt-b2-1",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T01:10:00.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 5200,
          process_name: "Code.exe",
          executable_path: "C:\\Users\\Bench\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
          command_line: '"C:\\Users\\Bench\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"',
          parent_pid: 1200,
          parent_process_name: "explorer.exe",
          username: "BENCH-USER",
        },
      },
      {
        kind: "process",
        event: {
          id: "evt-b2-2",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T01:10:05.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 5210,
          process_name: "node.exe",
          executable_path: "C:\\Program Files\\nodejs\\node.exe",
          command_line: "node index.js",
          parent_pid: 5200,
          parent_process_name: "Code.exe",
          username: "BENCH-USER",
        },
      },
    ],
  },
  {
    id: "scen-benign-03-office-editing",
    name: "Routine Document Creation & Saving",
    category: "BENIGN_ACTIVITY",
    description: "Microsoft Word editing document and saving to user Documents directory.",
    simulatedHours: 1.0,
    expectedRules: [],
    expectedStages: [],
    events: [
      {
        kind: "process",
        event: {
          id: "evt-b3-1",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T01:20:00.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 6100,
          process_name: "winword.exe",
          executable_path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
          command_line: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\Bench\\Documents\\report.docx"',
          parent_pid: 1200,
          parent_process_name: "explorer.exe",
          username: "BENCH-USER",
        },
      },
    ],
  },

  // 2. Suspicious Behavior Scenarios
  {
    id: "scen-suspicious-01-macro-encoded-ps",
    name: "Word Document Spawning Encoded PowerShell",
    category: "SUSPICIOUS_BEHAVIOR",
    description: "Microsoft Word process spawns PowerShell with an encoded command line payload.",
    simulatedHours: 0.5,
    expectedRules: ["PROC-001-SUSPICIOUS-PARENT-CHILD", "PROC-002-ENCODED-COMMAND-LINE"],
    expectedStages: ["EXECUTION", "PERSISTENCE"],
    events: [
      {
        kind: "process",
        event: {
          id: "evt-s1-1",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T02:00:00.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 7100,
          process_name: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAA...",
          parent_pid: 6100,
          parent_process_name: "winword.exe",
          username: "BENCH-USER",
        },
      },
    ],
  },
  {
    id: "scen-suspicious-02-reverse-shell-c2",
    name: "Interactive Shell Socket to Private Listener",
    category: "SUSPICIOUS_BEHAVIOR",
    description: "PowerShell process holding an established socket connection to remote port 4444.",
    simulatedHours: 0.5,
    expectedRules: ["NET-008-REVERSE-SHELL"],
    expectedStages: ["INITIAL_ACCESS", "EXECUTION"],
    events: [
      {
        kind: "network",
        event: {
          id: "evt-s2-1",
          type: "NETWORK_CONNECTION",
          origin: "snapshot",
          timestamp: "2026-10-10T02:10:00.000Z",
          source: "windows_network_monitor",
          hostname: "BENCH-HOST",
          pid: 7100,
          process_name: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          local_addr: "192.168.1.100",
          local_port: 49200,
          remote_addr: "10.0.2.15",
          remote_port: 4444,
          remote_role: "PRIVATE",
          state: "ESTABLISHED",
        },
      },
    ],
  },
  {
    id: "scen-suspicious-03-startup-persistence-credential",
    name: "Startup Folder Credential Dumping Script",
    category: "SUSPICIOUS_BEHAVIOR",
    description: "Script placed in Windows Startup directory containing mimikatz credential dumping primitives.",
    simulatedHours: 0.5,
    expectedRules: ["FILE-001-STARTUP-PERSISTENCE", "FILE-003-CREDENTIAL-ACCESS-ARTIFACT"],
    expectedStages: ["PERSISTENCE", "PRIVILEGE_ESCALATION"],
    events: [
      {
        kind: "file",
        event: {
          id: "evt-s3-1",
          type: "FILE_FINDING",
          origin: "snapshot",
          timestamp: "2026-10-10T02:20:00.000Z",
          source: "windows_file_monitor",
          hostname: "BENCH-HOST",
          pid: 0,
          process_name: "system",
          file_path: "C:\\Users\\Bench\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.ps1",
          file_name: "update.ps1",
          file_extension: "ps1",
          file_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          file_size: 1024,
          category: "startup-file lsass-access encoded-powershell",
          className: "persistence",
          finding_severity: "high",
          finding_reason: "Startup persistence with credential dumping primitives",
        },
      },
    ],
  },

  // 3. Coordinated Multi-Stage Scenario
  {
    id: "scen-multi-01-full-killchain",
    name: "Coordinated Multi-Stage Attack Killchain",
    category: "COORDINATED_MULTI_STAGE",
    description: "Multi-stage attack: Document launch -> Encoded Dropper -> Startup Persistence -> Reverse Shell -> Exfiltration.",
    simulatedHours: 1.0,
    expectedRules: [
      "PROC-001-SUSPICIOUS-PARENT-CHILD",
      "PROC-002-ENCODED-COMMAND-LINE",
      "FILE-001-STARTUP-PERSISTENCE",
      "NET-008-REVERSE-SHELL",
      "NET-009-DATA-EXFILTRATION",
    ],
    expectedStages: ["INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "EXFILTRATION"],
    events: [
      {
        kind: "process",
        event: {
          id: "evt-m1-1",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T03:00:00.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 8800,
          process_name: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -w hidden -e JABjAGwAaQBlAG4AdAA...",
          parent_pid: 6100,
          parent_process_name: "winword.exe",
          username: "BENCH-USER",
        },
      },
      {
        kind: "file",
        event: {
          id: "evt-m1-2",
          type: "FILE_FINDING",
          origin: "snapshot",
          timestamp: "2026-10-10T03:01:00.000Z",
          source: "windows_file_monitor",
          hostname: "BENCH-HOST",
          pid: 8800,
          process_name: "powershell.exe",
          file_path: "C:\\Users\\Bench\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\persist.ps1",
          file_name: "persist.ps1",
          file_extension: "ps1",
          file_hash: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
          file_size: 2048,
          category: "startup-file download-cradle",
          is_running: true,
          finding_severity: "high",
        },
      },
      {
        kind: "network",
        event: {
          id: "evt-m1-3",
          type: "NETWORK_CONNECTION",
          origin: "snapshot",
          timestamp: "2026-10-10T03:02:00.000Z",
          source: "windows_network_monitor",
          hostname: "BENCH-HOST",
          pid: 8800,
          process_name: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -w hidden -e JABjAGwAaQBlAG4AdAA... transfer exfil",
          local_addr: "192.168.1.100",
          local_port: 53100,
          remote_addr: "10.0.2.15",
          remote_port: 4444,
          remote_role: "PRIVATE",
          state: "ESTABLISHED",
        },
      },
      {
        kind: "network",
        event: {
          id: "evt-m1-4",
          type: "NETWORK_CONNECTION",
          origin: "snapshot",
          timestamp: "2026-10-10T03:03:00.000Z",
          source: "windows_network_monitor",
          hostname: "BENCH-HOST",
          pid: 8800,
          process_name: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -w hidden bitsadmin /transfer exfil",
          local_addr: "192.168.1.100",
          local_port: 53101,
          remote_addr: "10.0.2.15",
          remote_port: 8080,
          remote_role: "PRIVATE",
          state: "ESTABLISHED",
        },
      },
    ],
  },

  // 4. Edge Cases: Malformed, Missing Fields, Out-of-Order Events
  {
    id: "scen-edge-01-malformed-out-of-order",
    name: "Edge Cases: Malformed & Out-of-Order Telemetry",
    category: "EDGE_CASE_MALFORMED_OUT_OF_ORDER",
    description: "Telemetry events with missing parent PIDs, empty command lines, out-of-order timestamps, and duplicate IDs.",
    simulatedHours: 0.5,
    expectedRules: ["PROC-002-ENCODED-COMMAND-LINE"],
    expectedStages: ["EXECUTION"],
    events: [
      {
        kind: "process",
        event: {
          id: "evt-edge-1",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T04:05:00.000Z", // Out of order: later timestamp first
          source: "windows_process_monitor",
          hostname: null,
          pid: 9100,
          process_name: "powershell.exe",
          executable_path: undefined,
          command_line: "powershell.exe -EncodedCommand QQBBQQ...",
          parent_pid: null,
          parent_process_name: null,
        },
      },
      {
        kind: "process",
        event: {
          id: "evt-edge-1", // Duplicate event ID
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T04:00:00.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 9100,
          process_name: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -EncodedCommand QQBBQQ...",
          parent_pid: 0,
          parent_process_name: "System",
        },
      },
    ],
  },

  // 5. Ambiguous / Unknown Activity (Should NOT automatically become a confirmed threat)
  {
    id: "scen-ambiguous-01-custom-installer",
    name: "Ambiguous Activity: Custom Software Installer",
    category: "AMBIGUOUS_UNKNOWN",
    description: "Custom admin tool running `-ExecutionPolicy Bypass` without encoded payload or suspicious origin.",
    simulatedHours: 0.5,
    expectedRules: [],
    expectedStages: [],
    events: [
      {
        kind: "process",
        event: {
          id: "evt-amb-1",
          type: "PROCESS_CREATED",
          origin: "created",
          timestamp: "2026-10-10T05:00:00.000Z",
          source: "windows_process_monitor",
          hostname: "BENCH-HOST",
          pid: 9500,
          process_name: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -ExecutionPolicy Bypass -File C:\\Program Files\\CustomApp\\install.ps1",
          parent_pid: 9400,
          parent_process_name: "setup.exe",
          username: "BENCH-USER",
        },
      },
    ],
  },
];

// ---------------------------------------------------------------------------
// Benchmark Execution Engine
// ---------------------------------------------------------------------------

export class BenchmarkEvaluationEngine {
  /**
   * Run full regression evaluation across the entire benchmark dataset.
   */
  public evaluateBenchmark(): BenchmarkRunSummary {
    const startTime = Date.now();
    const scenarioResults: ScenarioBenchmarkResult[] = [];
    const ruleStatsMap = new Map<
      string,
      { tp: number; fp: number; tn: number; fn: number; count: number; ruleName: string }
    >();

    let grandTP = 0;
    let grandFP = 0;
    let grandTN = 0;
    let grandFN = 0;
    let grandSimulatedHours = 0;
    let grandEventsProcessed = 0;
    let grandLatencyTotalMs = 0;
    let top1Hits = 0;
    let top3Hits = 0;
    let evaluatedScenariosForPrediction = 0;
    let evidenceCount = 0;
    let totalDetections = 0;

    for (const scenario of BENCHMARK_SCENARIOS) {
      const engine = new DetectionEngine();
      engine.reset();

      const firedDetections: Detection[] = [];
      let scenarioLatencyMs = 0;

      // Ingest all scenario events into isolated detection engine instance
      for (const item of scenario.events) {
        const t0 = Date.now();
        if (item.kind === "process") {
          firedDetections.push(...engine.ingestEvent(item.event));
        } else if (item.kind === "network") {
          firedDetections.push(
            ...engine["evaluateMatches"](item.event, evaluateNetworkRules(item.event))
          );
        } else if (item.kind === "file") {
          firedDetections.push(
            ...engine["evaluateMatches"](item.event, evaluateFileRules(item.event))
          );
        }
        scenarioLatencyMs += Date.now() - t0;
      }

      grandEventsProcessed += scenario.events.length;
      grandSimulatedHours += scenario.simulatedHours;
      totalDetections += firedDetections.length;

      // Check evidence coverage
      for (const det of firedDetections) {
        if (det.evidence && Array.isArray(det.evidence) && det.evidence.length > 0) {
          evidenceCount++;
        }
      }

      const firedRuleIds = Array.from(new Set(firedDetections.map((d) => d.rule_id)));
      const expectedSet = new Set(scenario.expectedRules);
      const firedSet = new Set(firedRuleIds);

      const matchedRules = scenario.expectedRules.filter((r) => firedSet.has(r));
      const missedRules = scenario.expectedRules.filter((r) => !firedSet.has(r));
      const extraRules = firedRuleIds.filter((r) => !expectedSet.has(r));

      // Scenario TP, FP, TN, FN
      const tp = matchedRules.length;
      const fp = extraRules.length;
      const fn = missedRules.length;
      // TN = total inactive rules in catalog not expected and not fired
      const TOTAL_RULES_COUNT = 23;
      const tn = Math.max(0, TOTAL_RULES_COUNT - expectedSet.size - fp);

      grandTP += tp;
      grandFP += fp;
      grandTN += tn;
      grandFN += fn;

      const precision = tp + fp > 0 ? tp / (tp + fp) : scenario.expectedRules.length === 0 && fp === 0 ? 1.0 : 0.0;
      const recall = tp + fn > 0 ? tp / (tp + fn) : scenario.expectedRules.length === 0 ? 1.0 : 0.0;
      const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 1.0;
      const falsePositivesPerHour = scenario.simulatedHours > 0 ? fp / scenario.simulatedHours : fp;
      const avgLatencyMs = scenario.events.length > 0 ? Math.round((scenarioLatencyMs / scenario.events.length) * 100) / 100 : 0;
      grandLatencyTotalMs += scenarioLatencyMs;

      // Evaluate Attack-Stage Prediction Top-1 and Top-3 accuracy against scenario ground truth
      const predictions = generatePredictions([], firedDetections);
      let top1Hit = false;
      let top3Hit = false;

      if (scenario.expectedStages.length > 0) {
        evaluatedScenariosForPrediction++;
        const targetStage = scenario.expectedStages[0];
        const top1Stage = predictions[0]?.stage;
        const top3Stages = predictions.slice(0, 3).map((p) => p.stage);

        if (top1Stage === targetStage) top1Hit = true;
        if (top3Stages.includes(targetStage)) top3Hit = true;

        if (top1Hit) top1Hits++;
        if (top3Hit) top3Hits++;
      } else {
        // Benign scenario: prediction is correct if top prediction is insufficient_evidence or no high-confidence threat
        if (predictions.length === 0 || predictions[0].confidence < 0.6) {
          top1Hit = true;
          top3Hit = true;
        }
      }

      const evidenceCoverage = firedDetections.length > 0 ? Math.round((evidenceCount / firedDetections.length) * 100) / 100 : 1.0;

      scenarioResults.push({
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        category: scenario.category,
        simulatedHours: scenario.simulatedHours,
        totalEvents: scenario.events.length,
        expectedRules: scenario.expectedRules,
        firedRules: firedRuleIds,
        matchedRules,
        missedRules,
        extraRules,
        truePositives: tp,
        falsePositives: fp,
        trueNegatives: tn,
        falseNegatives: fn,
        precision: Math.round(precision * 100) / 100,
        recall: Math.round(recall * 100) / 100,
        f1Score: Math.round(f1Score * 100) / 100,
        falsePositivesPerHour: Math.round(falsePositivesPerHour * 100) / 100,
        avgLatencyMs,
        predictionTop1Hit: top1Hit,
        predictionTop3Hit: top3Hit,
        evidenceCoverage,
        topPredictions: predictions.slice(0, 3),
      });

      // Update per-rule statistics
      for (const rId of scenario.expectedRules) {
        const stats = ruleStatsMap.get(rId) ?? { tp: 0, fp: 0, tn: 0, fn: 0, count: 0, ruleName: rId };
        stats.count++;
        if (firedSet.has(rId)) {
          stats.tp++;
        } else {
          stats.fn++;
        }
        ruleStatsMap.set(rId, stats);
      }
      for (const rId of extraRules) {
        const stats = ruleStatsMap.get(rId) ?? { tp: 0, fp: 0, tn: 0, fn: 0, count: 0, ruleName: rId };
        stats.count++;
        stats.fp++;
        ruleStatsMap.set(rId, stats);
      }
    }

    // Compute aggregate metrics
    const aggPrecision = grandTP + grandFP > 0 ? grandTP / (grandTP + grandFP) : 1.0;
    const aggRecall = grandTP + grandFN > 0 ? grandTP / (grandTP + grandFN) : 1.0;
    const aggF1 = aggPrecision + aggRecall > 0 ? (2 * aggPrecision * aggRecall) / (aggPrecision + aggRecall) : 1.0;
    const aggFpPerHour = grandSimulatedHours > 0 ? grandFP / grandSimulatedHours : 0;
    const aggAvgLatencyMs = grandEventsProcessed > 0 ? Math.round((grandLatencyTotalMs / grandEventsProcessed) * 100) / 100 : 0;
    const top1Accuracy = evaluatedScenariosForPrediction > 0 ? Math.round((top1Hits / evaluatedScenariosForPrediction) * 100) / 100 : 1.0;
    const top3Accuracy = evaluatedScenariosForPrediction > 0 ? Math.round((top3Hits / evaluatedScenariosForPrediction) * 100) / 100 : 1.0;
    const overallEvidenceCoverage = totalDetections > 0 ? Math.round((evidenceCount / totalDetections) * 100) / 100 : 1.0;

    const ruleResults: RuleBenchmarkResult[] = Array.from(ruleStatsMap.entries()).map(([ruleId, stats]) => {
      const p = stats.tp + stats.fp > 0 ? stats.tp / (stats.tp + stats.fp) : 1.0;
      const r = stats.tp + stats.fn > 0 ? stats.tp / (stats.tp + stats.fn) : 1.0;
      const f1 = p + r > 0 ? (2 * p * r) / (p + r) : 1.0;
      return {
        ruleId,
        ruleName: stats.ruleName,
        truePositives: stats.tp,
        falsePositives: stats.fp,
        trueNegatives: stats.tn,
        falseNegatives: stats.fn,
        precision: Math.round(p * 100) / 100,
        recall: Math.round(r * 100) / 100,
        f1Score: Math.round(f1 * 100) / 100,
        sampleCount: stats.count,
      };
    });

    return {
      timestamp: new Date().toISOString(),
      datasetLabel: "SYNTHETIC_LAB_BENCHMARK_V1",
      isSyntheticDataset: true,
      totalScenarios: BENCHMARK_SCENARIOS.length,
      totalEventsProcessed: grandEventsProcessed,
      totalSimulatedHours: Math.round(grandSimulatedHours * 10) / 10,
      aggregateMetrics: {
        truePositives: grandTP,
        falsePositives: grandFP,
        trueNegatives: grandTN,
        falseNegatives: grandFN,
        precision: Math.round(aggPrecision * 100) / 100,
        recall: Math.round(aggRecall * 100) / 100,
        f1Score: Math.round(aggF1 * 100) / 100,
        falsePositivesPerHour: Math.round(aggFpPerHour * 100) / 100,
        avgLatencyMs: aggAvgLatencyMs,
        predictionTop1Accuracy: top1Accuracy,
        predictionTop3Accuracy: top3Accuracy,
        evidenceCoverage: overallEvidenceCoverage,
      },
      scenarioResults,
      ruleResults,
      disclaimer:
        "BENCHMARK DISCLAIMER: These results are derived from a deterministic synthetic lab dataset for PS-24 validation. Synthetic test metrics do not establish real-world detection accuracy under unconstrained enterprise environment noise.",
    };
  }
}

export const benchmarkEvaluationEngine = new BenchmarkEvaluationEngine();
