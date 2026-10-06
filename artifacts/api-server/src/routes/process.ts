
import { Router, type IRouter, type Request, type Response } from "express";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { eventHub, type ProcessEvent, type ProcessSnapshot } from "../lib/event-hub";
import { detectionEngine } from "../detection/engine";

const execAsync = promisify(exec);

const router: IRouter = Router();

/**
 * POST /api/events/process
 * Accept one or more process events from the security engine.
 */
router.post("/events/process", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || (typeof body !== "object" && !Array.isArray(body))) {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a process event object or array of events.",
    });
    return;
  }

  const events: ProcessEvent[] = Array.isArray(body) ? body : [body];
  const validated: ProcessEvent[] = [];
  const errors: Array<{ index: number; error: string }> = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const validation = validateProcessEvent(event);
    if (validation.valid) {
      validated.push(event);
    } else {
      errors.push({ index: i, error: validation.error });
    }
  }

  // Enforce payload size limit: max 100 events per batch
  if (validated.length > 100) {
    res.status(413).json({
      error: "Payload too large",
      detail: "Maximum 100 events per batch.",
    });
    return;
  }

  for (const event of validated) {
    eventHub.addEvent(event);
    // Run deterministic detection over real telemetry and surface any findings.
    const detections = detectionEngine.ingestEvent(event);
    for (const detection of detections) {
      eventHub.addDetection(detection);
    }
  }

  if (errors.length > 0 && validated.length === 0) {
    res.status(422).json({
      error: "Validation failed",
      details: errors,
    });
    return;
  }

  res.status(201).json({
    accepted: validated.length,
    rejected: errors.length,
    ...(errors.length > 0 ? { errors } : {}),
  });
});

/**
 * GET /api/events/process
 * Retrieve recent process events.
 */
router.get("/events/process", (req: Request, res: Response) => {
  const eventType =
    typeof req.query.event_type === "string" ? req.query.event_type : undefined;
  const limit = Math.min(
    parseInt(String(req.query.limit ?? "100"), 10) || 100,
    500,
  );

  const events = eventHub.getEvents(eventType, limit);
  res.json({ events, count: events.length });
});

/**
 * GET /api/events/process/stream
 * SSE endpoint for real-time process event streaming.
 */
router.get("/events/process/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Send initial connection event
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString() })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["process"]);

  // Heartbeat to keep connection alive
  const heartbeat = setInterval(() => {
    try {
      res.write(": heartbeat\n\n");
    } catch {
      clearInterval(heartbeat);
      eventHub.removeSSEClient(clientId);
    }
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    eventHub.removeSSEClient(clientId);
  });
});

/**
 * POST /api/processes
 * Accept a full process snapshot from the security engine.
 */
router.post("/processes", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a process snapshot object.",
    });
    return;
  }

  if (!Array.isArray(body.processes)) {
    res.status(400).json({
      error: "Invalid snapshot",
      detail: "Snapshot must contain a 'processes' array.",
    });
    return;
  }

  // Enforce size limit: max 10000 processes
  if (body.processes.length > 10000) {
    res.status(413).json({
      error: "Snapshot too large",
      detail: "Maximum 10000 processes per snapshot.",
    });
    return;
  }

  const snapshot: ProcessSnapshot = {
    timestamp: body.timestamp || new Date().toISOString(),
    total_count: body.total_count || body.processes.length,
    access_denied_count: body.access_denied_count || 0,
    processes: body.processes,
  };

  eventHub.setSnapshot(snapshot);

  // Accept the snapshot into the detection engine once (gate on timestamp).
  const detections = detectionEngine.ingestSnapshot(snapshot);
  for (const detection of detections) {
    eventHub.addDetection(detection);
  }

  res.status(201).json({
    accepted: true,
    process_count: body.processes.length,
  });
});

/**
 * Fallback: query running Windows processes directly via PowerShell if the security
 * engine has not yet delivered a psutil snapshot.
 */
async function queryWindowsProcesses(): Promise<ProcessSnapshot | null> {
  try {
    const { stdout } = await execAsync(
      `powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CommandLine, ExecutablePath, WorkingSetSize | ConvertTo-Json -Compress"`,
      { maxBuffer: 15 * 1024 * 1024, timeout: 6000 }
    );
    if (!stdout.trim()) return null;
    const raw = JSON.parse(stdout);
    const list = Array.isArray(raw) ? raw : [raw];
    const processes = list
      .filter((p: any) => p && p.ProcessId != null)
      .map((p: any) => ({
        pid: Number(p.ProcessId) || 0,
        name: String(p.Name || "unknown.exe"),
        executable_path: p.ExecutablePath ? String(p.ExecutablePath) : undefined,
        command_line: p.CommandLine ? String(p.CommandLine) : undefined,
        parent_pid: p.ParentProcessId != null ? Number(p.ParentProcessId) : undefined,
        memory_bytes: p.WorkingSetSize ? Number(p.WorkingSetSize) : undefined,
        cpu_percent: 0.1,
        status: "running",
      }));

    return {
      timestamp: new Date().toISOString(),
      total_count: processes.length,
      access_denied_count: 0,
      processes,
    };
  } catch {
    return null;
  }
}

/**
 * GET /api/processes
 * Retrieve the current process snapshot.
 */
router.get("/processes", async (_req: Request, res: Response) => {
  let snapshot = eventHub.getSnapshot();
  if (!snapshot || snapshot.processes.length === 0) {
    const fallback = await queryWindowsProcesses();
    if (fallback && fallback.processes.length > 0) {
      eventHub.setSnapshot(fallback);
      snapshot = fallback;
    }
  }

  if (!snapshot) {
    res.json({
      timestamp: null,
      total_count: 0,
      access_denied_count: 0,
      processes: [],
      message: "No snapshot available. Start the security engine to populate.",
    });
    return;
  }
  res.json(snapshot);
});

/** Validate required fields of a process event. */
function validateProcessEvent(event: unknown): { valid: true } | { valid: false; error: string } {
  if (!event || typeof event !== "object") {
    return { valid: false, error: "Event must be an object" };
  }
  const e = event as Record<string, unknown>;

  if (typeof e.pid !== "number") {
    return { valid: false, error: "pid must be a number" };
  }
  if (typeof e.process_name !== "string") {
    return { valid: false, error: "process_name must be a string" };
  }
  if (typeof e.event_type !== "string") {
    return { valid: false, error: "event_type must be a string" };
  }
  if (
    e.event_type !== "PROCESS_STARTED" &&
    e.event_type !== "PROCESS_TERMINATED" &&
    e.event_type !== "SNAPSHOT"
  ) {
    return {
      valid: false,
      error: `event_type must be PROCESS_STARTED, PROCESS_TERMINATED, or SNAPSHOT`,
    };
  }
  return { valid: true };
}

export async function terminateProcessTree(pid: number, procName = `PID ${pid}`): Promise<{ success: boolean; error?: string; detail?: string }> {
  if (isNaN(pid) || pid <= 0) {
    return { success: false, error: "Invalid PID" };
  }
  if (pid === 0 || pid === 4) {
    return { success: false, error: "Cannot terminate core OS system process (PID 0/4)" };
  }

  if (process.platform === "win32") {
    const { execFile } = await import("child_process");
    return new Promise((resolve) => {
      execFile("taskkill", ["/F", "/T", "/PID", String(pid)], (error, stdout, stderr) => {
        const combined = `${stdout} ${stderr}`;
        const isNotFound = combined.toLowerCase().includes("not found") || combined.toLowerCase().includes("no running instance");
        const isAccessDenied = combined.toLowerCase().includes("access is denied");

        if (error && !isNotFound) {
          resolve({
            success: false,
            error: isAccessDenied
              ? "Access denied: elevated administrator privileges required to terminate this process."
              : `Termination failed: ${combined.trim() || error.message}`,
            detail: combined.trim(),
          });
          return;
        }

        eventHub.addEvent({
          id: `term-${pid}-${Date.now()}`,
          event_type: "PROCESS_TERMINATED",
          timestamp: new Date().toISOString(),
          pid,
          process_name: procName,
          source: "remediation_action",
          observed: true,
        });

        resolve({ success: true });
      });
    });
  } else {
    try {
      process.kill(pid, "SIGKILL");
      eventHub.addEvent({
        id: `term-${pid}-${Date.now()}`,
        event_type: "PROCESS_TERMINATED",
        timestamp: new Date().toISOString(),
        pid,
        process_name: procName,
        source: "remediation_action",
        observed: true,
      });
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err?.message || "Termination failed" };
    }
  }
}

/**
 * POST /api/processes/:pid/terminate
 * Terminate a process by PID and emit a PROCESS_TERMINATED event.
 */
router.post("/processes/:pid/terminate", async (req: Request, res: Response) => {
  const rawPid = Array.isArray(req.params.pid) ? req.params.pid[0] : req.params.pid;
  const pid = parseInt(String(rawPid), 10);
  if (isNaN(pid) || pid <= 0) {
    res.status(400).json({ error: "Invalid PID" });
    return;
  }
  if (pid === 0 || pid === 4) {
    res.status(403).json({ error: "Cannot terminate core OS system process (PID 0/4)" });
    return;
  }

  const procName = typeof req.body?.name === "string" ? req.body.name : `PID ${pid}`;
  const result = await terminateProcessTree(pid, procName);

  if (!result.success) {
    const isAccessDenied = (result.error || "").toLowerCase().includes("access denied");
    res.status(isAccessDenied ? 403 : 500).json(result);
    return;
  }

  res.json({
    success: true,
    pid,
    message: `Process ${procName} (PID ${pid}) was successfully terminated.`,
  });
});

export default router;
