import { Router, type Request, type Response, type IRouter } from "express";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { logger } from "../lib/logger";

const router: IRouter = Router();

export type ReportEvidenceCounts = {
  processes: number;
  connections: number;
  quarantined: number;
  detections: number;
  timelineEvents: number;
};

export type ReportRecord = {
  id: string;
  incidentId: string;
  title: string;
  author: string;
  createdAt: string;
  status: "Ready" | "Shared" | "Archived";
  format: "PDF" | "JSON" | "TXT";
  audience: string;
  riskScore: number;
  endpoint: string;
  summary: string;
  evidenceCounts: ReportEvidenceCounts;
  metrics?: {
    cpu?: string;
    ram?: string;
    uptime?: string;
  };
  quarantinedArtifacts?: Array<{
    id: string;
    name: string;
    hash: string;
    size: string;
    status: string;
  }>;
  suspiciousProcesses?: Array<{
    pid: number;
    name: string;
    cmdline?: string;
  }>;
  externalConnections?: Array<{
    destination: string;
    port: number;
    process: string;
  }>;
  content?: string;
  filePath?: string;
};

// Vault directory for report archives
const VAULT_DIR = path.resolve(process.cwd(), "artifacts", "reports_vault");
const REPORTS_DIR = path.join(VAULT_DIR, "saved_reports");
const MANIFEST_PATH = path.join(VAULT_DIR, "manifest.json");

function ensureReportsVaultInitialized(): void {
  try {
    if (!fs.existsSync(REPORTS_DIR)) {
      fs.mkdirSync(REPORTS_DIR, { recursive: true });
    }

    if (!fs.existsSync(MANIFEST_PATH)) {
      const defaultRecords: ReportRecord[] = [
        {
          id: "RPT-2026-0041",
          incidentId: "INC-2026-1042",
          title: "Executive Exposure Assessment · Host WS-0427",
          author: "Lead Forensic Investigator",
          createdAt: new Date(Date.now() - 7200000).toLocaleString(),
          status: "Ready",
          format: "PDF",
          audience: "Security Leadership & CISO",
          riskScore: 78,
          endpoint: "WS-0427 (Windows Host)",
          summary: "Suspicious PowerShell execution correlated with sensitive document staging and outbound C2 connection attempt. Endpoint isolated in quarantine vault with zero data loss.",
          evidenceCounts: {
            processes: 274,
            connections: 752,
            quarantined: 3,
            detections: 4,
            timelineEvents: 18,
          },
          metrics: {
            cpu: "8.4%",
            ram: "58.2%",
            uptime: "2d 4h",
          },
        },
        {
          id: "RPT-2026-0040",
          incidentId: "INC-2026-1039",
          title: "Unsigned Binary Review & Memory Handle Triage",
          author: "SecOps Tier-3 Analyst",
          createdAt: new Date(Date.now() - 86400000).toLocaleString(),
          status: "Shared",
          format: "PDF",
          audience: "Incident Response Team",
          riskScore: 65,
          endpoint: "WS-0198 (Finance Terminal)",
          summary: "First-seen executable invoice_viewer.exe sequestered to evidence vault. Tamper seal verified with 100% cryptographic integrity.",
          evidenceCounts: {
            processes: 185,
            connections: 240,
            quarantined: 2,
            detections: 2,
            timelineEvents: 12,
          },
        },
        {
          id: "RPT-2026-0039",
          incidentId: "BATCH-2026-Q3",
          title: "Quarterly Host Integrity & Regulatory Audit",
          author: "Cyber Risk & Compliance",
          createdAt: new Date(Date.now() - 604800000).toLocaleString(),
          status: "Archived",
          format: "JSON",
          audience: "Legal & Compliance",
          riskScore: 32,
          endpoint: "Enterprise Monitored Fleet",
          summary: "Periodic integrity audit across active endpoint sensors. Zero active backdoors detected.",
          evidenceCounts: {
            processes: 290,
            connections: 810,
            quarantined: 0,
            detections: 0,
            timelineEvents: 85,
          },
        },
      ];

      fs.writeFileSync(MANIFEST_PATH, JSON.stringify(defaultRecords, null, 2), "utf8");
    }
  } catch (err) {
    logger.error({ err }, "Failed to initialize reports vault");
  }
}

function readReportsManifest(): ReportRecord[] {
  ensureReportsVaultInitialized();
  try {
    const raw = fs.readFileSync(MANIFEST_PATH, "utf8");
    const records = JSON.parse(raw);
    return Array.isArray(records) ? records : [];
  } catch (err) {
    logger.error({ err }, "Failed to read reports manifest");
    return [];
  }
}

function writeReportsManifest(records: ReportRecord[]): void {
  ensureReportsVaultInitialized();
  try {
    fs.writeFileSync(MANIFEST_PATH, JSON.stringify(records, null, 2), "utf8");
  } catch (err) {
    logger.error({ err }, "Failed to write reports manifest");
  }
}

// GET /api/reports — List all archived incident reports
router.get("/reports", (_req: Request, res: Response): void => {
  try {
    const reports = readReportsManifest();
    res.json({
      success: true,
      total: reports.length,
      vaultPath: VAULT_DIR,
      reports,
    });
  } catch (err) {
    logger.error({ err }, "Error reading reports archive");
    res.status(500).json({ success: false, error: "Failed to read reports archive" });
  }
});

// GET /api/reports/:id — Retrieve specific report
router.get("/reports/:id", (req: Request, res: Response): void => {
  try {
    const { id } = req.params;
    const reports = readReportsManifest();
    const found = reports.find((r) => r.id === id || r.incidentId === id);

    if (!found) {
      res.status(404).json({ success: false, error: "Report not found" });
      return;
    }

    res.json({ success: true, report: found });
  } catch (err) {
    logger.error({ err }, "Error reading report by id");
    res.status(500).json({ success: false, error: "Failed to read report" });
  }
});

// POST /api/reports — Save new generated incident report to archive
router.post("/reports", (req: Request, res: Response): void => {
  try {
    const body = req.body;
    if (!body || !body.title) {
      res.status(400).json({ success: false, error: "Report title is required" });
      return;
    }

    const reports = readReportsManifest();
    const id = `RPT-${new Date().getFullYear()}-${String(Date.now()).slice(-4)}`;
    const incidentId = body.incidentId || `INC-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;

    const newReport: ReportRecord = {
      id,
      incidentId,
      title: body.title,
      author: body.author || "SecOps Analyst",
      createdAt: new Date().toLocaleString(),
      status: body.status || "Ready",
      format: body.format || "PDF",
      audience: body.audience || "Incident Response & Leadership",
      riskScore: typeof body.riskScore === "number" ? body.riskScore : 72,
      endpoint: body.endpoint || "WS-0427 (Windows Host)",
      summary: body.summary || "Real-time incident dossier compiled from ARGUS live telemetry.",
      evidenceCounts: body.evidenceCounts || {
        processes: body.processesCount || 0,
        connections: body.connectionsCount || 0,
        quarantined: body.quarantineCount || 0,
        detections: body.detectionsCount || 0,
        timelineEvents: body.timelineEventsCount || 0,
      },
      metrics: body.metrics,
      quarantinedArtifacts: body.quarantinedArtifacts,
      suspiciousProcesses: body.suspiciousProcesses,
      externalConnections: body.externalConnections,
      content: body.content,
    };

    // Optionally write report file to disk
    if (body.content) {
      const ext = body.format === "JSON" ? "json" : body.format === "TXT" ? "txt" : "html";
      const fileName = `${id}_${incidentId}.${ext}`;
      const filePath = path.join(REPORTS_DIR, fileName);
      try {
        fs.writeFileSync(filePath, body.content, "utf8");
        newReport.filePath = filePath;
      } catch (fErr) {
        logger.warn({ fErr }, "Could not persist standalone report file, saved metadata only");
      }
    }

    // Prepend to manifest
    reports.unshift(newReport);
    writeReportsManifest(reports);

    logger.info({ reportId: id, incidentId }, "Archived new incident report");
    res.status(201).json({ success: true, report: newReport });
  } catch (err) {
    logger.error({ err }, "Failed to archive report");
    res.status(500).json({ success: false, error: "Failed to archive incident report" });
  }
});

// DELETE /api/reports/:id — Delete an archived report
router.delete("/reports/:id", (req: Request, res: Response): void => {
  try {
    const { id } = req.params;
    const reports = readReportsManifest();
    const index = reports.findIndex((r) => r.id === id);

    if (index === -1) {
      res.status(404).json({ success: false, error: "Report not found" });
      return;
    }

    const [deleted] = reports.splice(index, 1);
    writeReportsManifest(reports);

    // Remove file if exists
    if (deleted.filePath && fs.existsSync(deleted.filePath)) {
      try {
        fs.unlinkSync(deleted.filePath);
      } catch {}
    }

    logger.info({ reportId: id }, "Purged report from archive");
    res.json({ success: true, message: `Report ${id} permanently removed`, deleted });
  } catch (err) {
    logger.error({ err }, "Failed to delete report");
    res.status(500).json({ success: false, error: "Failed to delete report" });
  }
});

export default router;
