import { Router, type IRouter, type Request, type Response } from "express";
import { eventHub, type NetworkSnapshot, type PortIntelligenceSnapshot } from "../lib/event-hub";
import { detectionEngine } from "../detection/engine";

const router: IRouter = Router();

/**
 * POST /api/network/connections
 * Accept a network connection snapshot from the security engine.
 * Stores the latest snapshot and broadcasts it to SSE clients.
 */
router.post("/network/connections", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a network snapshot object.",
    });
    return;
  }

  if (!Array.isArray(body.connections)) {
    res.status(400).json({
      error: "Invalid snapshot",
      detail: "Snapshot must contain a 'connections' array.",
    });
    return;
  }

  if (body.connections.length > 5000) {
    res.status(413).json({
      error: "Snapshot too large",
      detail: "Maximum 5000 connections per snapshot.",
    });
    return;
  }

  const snapshot: NetworkSnapshot = {
    ...body,
    timestamp: body.timestamp || new Date().toISOString(),
    total_count: body.total_count || body.connections.length,
    established_count: body.established_count || 0,
    listen_count: body.listen_count || 0,
    connections: body.connections,
  };

  eventHub.setNetworkSnapshot(snapshot);

  // Evaluate the real connection telemetry against the NET rule set and
  // broadcast any new network detections.
  const detections = detectionEngine.ingestNetworkSnapshot(snapshot);
  for (const detection of detections) {
    eventHub.addDetection(detection);
  }

  res.status(201).json({
    accepted: true,
    connection_count: body.connections.length,
  });
});

/**
 * GET /api/network/events
 * Retrieve the bounded, chronological history of connection lifecycle events
 * (NEW, CLOSED, STATE_CHANGE, plus infra events) observed by the engine.
 */
router.get("/network/events", (req: Request, res: Response) => {
  const rawLimit = Number(req.query.limit);
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 1000) : 200;
  const events = eventHub.getTopologyEvents(limit);
  res.json({ events, count: events.length });
});

/**
 * GET /api/network/connections
 * Retrieve the current network connection snapshot.
 */
router.get("/network/connections", (_req: Request, res: Response) => {
  const snapshot = eventHub.getNetworkSnapshot();
  if (!snapshot) {
    res.json({
      timestamp: null,
      total_count: 0,
      established_count: 0,
      listen_count: 0,
      connections: [],
      message: "No network data available. Start the security engine to populate.",
    });
    return;
  }
  res.json(snapshot);
});

/**
 * GET /api/network/connections/stream
 * SSE endpoint for real-time network connection streaming.
 */
router.get("/network/connections/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Send initial connection event with current snapshot if available
  const current = eventHub.getNetworkSnapshot();
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString(), ...(current ? { snapshot: current } : {}) })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["network.connections"]);

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
 * POST /api/network/topology
 * Accept a comprehensive network topology snapshot from the security engine.
 * Stores the latest snapshot and broadcasts it to SSE clients.
 */
router.post("/network/topology", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a network topology snapshot object.",
    });
    return;
  }

  if (!Array.isArray(body.interfaces) || !Array.isArray(body.connections)) {
    res.status(400).json({
      error: "Invalid snapshot",
      detail: "Snapshot must contain 'interfaces' and 'connections' arrays.",
    });
    return;
  }

  if (body.connections.length > 10000) {
    res.status(413).json({
      error: "Snapshot too large",
      detail: "Maximum 10000 connections per snapshot.",
    });
    return;
  }

  eventHub.setTopologySnapshot({
    ...body,
    timestamp: body.timestamp || new Date().toISOString(),
    hostname: body.hostname || "",
    interfaces: body.interfaces || [],
    default_gateway: body.default_gateway || {},
    dns_servers: body.dns_servers || [],
    connections: body.connections || [],
    traffic_rates: body.traffic_rates || [],
    neighbors: body.neighbors || [],
    connection_events: body.connection_events || [],
    public_ip: body.public_ip || "",
    udp_endpoints: body.udp_endpoints || 0,
    tcp_listening: body.tcp_listening || 0,
    total_connections: body.total_connections || body.connections.length,
    established_count: body.established_count || 0,
    listen_count: body.listen_count || 0,
  });

  res.status(201).json({
    accepted: true,
    connection_count: body.connections.length,
  });
});

/**
 * GET /api/network/topology
 * Retrieve the current network topology snapshot.
 */
router.get("/network/topology", (_req: Request, res: Response) => {
  const snapshot = eventHub.getTopologySnapshot();
  if (!snapshot) {
    res.json({
      timestamp: null,
      hostname: "",
      interfaces: [],
      default_gateway: {},
      dns_servers: [],
      connections: [],
      traffic_rates: [],
      neighbors: [],
      connection_events: [],
      public_ip: "",
      udp_endpoints: 0,
      tcp_listening: 0,
      total_connections: 0,
      established_count: 0,
      listen_count: 0,
      message: "No network topology data available. Start the security engine to populate.",
    });
    return;
  }
  res.json(snapshot);
});

/**
 * GET /api/network/topology/stream
 * SSE endpoint for real-time network topology streaming.
 */
router.get("/network/topology/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Send initial connection event with current snapshot if available
  const current = eventHub.getTopologySnapshot();
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString(), ...(current ? { snapshot: current } : {}) })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["network.topology", "network.connection_events"]);

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
 * POST /api/network/ports
 * Accept a port intelligence snapshot from the security engine.
 * Stores the latest snapshot, buffers PORT_OPENED/PORT_CLOSED/PORT_CHANGED
 * events, and broadcasts to SSE clients.
 */
router.post("/network/ports", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a port intelligence snapshot object.",
    });
    return;
  }

  if (!Array.isArray(body.tcp_listening) || !Array.isArray(body.udp_endpoints)) {
    res.status(400).json({
      error: "Invalid snapshot",
      detail: "Snapshot must contain 'tcp_listening' and 'udp_endpoints' arrays.",
    });
    return;
  }

  if (body.tcp_listening.length + body.udp_endpoints.length > 10000) {
    res.status(413).json({
      error: "Snapshot too large",
      detail: "Maximum 10000 total ports per snapshot.",
    });
    return;
  }

  const snapshot: PortIntelligenceSnapshot = {
    timestamp: body.timestamp || new Date().toISOString(),
    tcp_listening: body.tcp_listening || [],
    udp_endpoints: body.udp_endpoints || [],
    port_events: body.port_events || [],
    summary: body.summary || {},
    active_tcp_connections: body.active_tcp_connections || 0,
  };

  eventHub.setPorts(snapshot);

  // Evaluate port telemetry (listeners, endpoints, PORT_OPENED events) against
  // the NET rule set and broadcast any new network detections.
  const detections = detectionEngine.ingestPortSnapshot(snapshot);
  for (const detection of detections) {
    eventHub.addDetection(detection);
  }

  res.status(201).json({
    accepted: true,
    tcp_listening_count: (body.tcp_listening || []).length,
    udp_endpoint_count: (body.udp_endpoints || []).length,
  });
});

/**
 * GET /api/network/ports
 * Retrieve the current port intelligence snapshot.
 */
router.get("/network/ports", (_req: Request, res: Response) => {
  const snapshot = eventHub.getPorts();
  if (!snapshot) {
    res.json({
      timestamp: null,
      tcp_listening: [],
      udp_endpoints: [],
      port_events: [],
      summary: {},
      active_tcp_connections: 0,
      message: "No port data available. Start the security engine to populate.",
    });
    return;
  }
  res.json(snapshot);
});

/**
 * GET /api/network/ports/events
 * Retrieve the bounded history of port lifecycle events.
 */
router.get("/network/ports/events", (req: Request, res: Response) => {
  const rawLimit = Number(req.query.limit);
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 1000) : 200;
  const events = eventHub.getPortEvents(limit);
  res.json({ events, count: events.length });
});

/**
 * GET /api/network/ports/stream
 * SSE endpoint for real-time port intelligence streaming.
 * Emits PORT_OPENED, PORT_CLOSED, and PORT_CHANGED events as they occur.
 */
router.get("/network/ports/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Send initial connection event with current snapshot if available
  const current = eventHub.getPorts();
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString(), ...(current ? { snapshot: current } : {}) })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["network.ports", "network.port_events"]);

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

export default router;
