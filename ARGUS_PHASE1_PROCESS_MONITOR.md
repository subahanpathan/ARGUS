# ARGUS Phase 1 — Real Windows Process Monitoring

## Architecture

```
ARGUS React UI (port 5173)
    ↓ fetch + EventSource (SSE)
ARGUS API Server (port 5000)
    ↓ in-memory event hub
Windows Process Monitor (Python)
    ↓ psutil (read-only)
Windows OS
```

The three components are independently runnable. The UI falls back to demo data when the engine and API are offline.

## Files Created

### Security Engine (Python)
| File | Purpose |
|------|---------|
| `artifacts/security-engine/main.py` | Entry point — starts watcher, delivers events |
| `artifacts/security-engine/config.py` | Central configuration (poll interval, API URL) |
| `artifacts/security-engine/requirements.txt` | Python dependencies (psutil) |
| `artifacts/security-engine/process_monitor/__init__.py` | Package exports |
| `artifacts/security-engine/process_monitor/models.py` | Normalized data models (ProcessEvent, ProcessInfo, ProcessSnapshot) |
| `artifacts/security-engine/process_monitor/snapshot.py` | One-shot full process enumeration |
| `artifacts/security-engine/process_monitor/watcher.py` | Continuous polling watcher (detects starts/terminations) |
| `artifacts/security-engine/api_client/__init__.py` | Package exports |
| `artifacts/security-engine/api_client/client.py` | HTTP client for API delivery (stdlib urllib) |

### API Server (Node.js/Express)
| File | Purpose |
|------|---------|
| `artifacts/api-server/src/routes/process.ts` | Process API endpoints (POST events, GET processes, SSE stream) |
| `artifacts/api-server/src/lib/event-hub.ts` | In-memory event hub + SSE client management |

### Shared Libraries
| File | Purpose |
|------|---------|
| `lib/api-spec/openapi.yaml` | Updated OpenAPI spec with process/event schemas |
| `lib/api-zod/src/generated/api.ts` | Zod validators for process/event types |
| `lib/api-zod/src/generated/types/processEvent.ts` | ProcessEvent TypeScript interface |
| `lib/api-zod/src/generated/types/processInfo.ts` | ProcessInfo TypeScript interface |
| `lib/api-zod/src/generated/types/processSnapshot.ts` | ProcessSnapshot TypeScript interface |
| `lib/api-zod/src/generated/types/processEventList.ts` | ProcessEventList TypeScript interface |
| `lib/api-zod/src/generated/types/eventIngestResponse.ts` | EventIngestResponse TypeScript interface |
| `lib/api-zod/src/generated/types/snapshotIngestResponse.ts` | SnapshotIngestResponse TypeScript interface |
| `lib/db/src/schema/processEvents.ts` | Drizzle schema for future DB persistence |

### Frontend
| File | Purpose |
|------|---------|
| `artifacts/argus/src/hooks/use-process-monitor.ts` | React hook for SSE process event consumption |

## Files Modified

| File | Change |
|------|--------|
| `artifacts/api-server/src/routes/index.ts` | Added process router import |
| `artifacts/argus/src/App.tsx` | Integrated process monitor hook, updated ProcessesPage with real/demo toggle |
| `artifacts/argus/vite.config.ts` | Added `/api` proxy to API server |
| `lib/api-zod/src/generated/types/index.ts` | Added exports for new type files |
| `lib/db/src/schema/index.ts` | Added processEvents export |

## Dependencies Added

### Python
- `psutil>=5.9.0,<7.0.0` — Cross-platform process and system utilities

### Node.js
No new npm dependencies were added. All TypeScript types use existing zod/express patterns.

## How to Start

### 1. Install Python dependencies
```bash
cd artifacts/security-engine
pip install -r requirements.txt
```

### 2. Start the API server
```bash
pnpm --filter @workspace/api-server run dev
```
The API server starts on port 5000 by default.

### 3. Start the process monitor
```bash
cd artifacts/security-engine
python main.py --api --snapshot
```

Command-line options:
- `--api` — Send events to the API server
- `--snapshot` — Send initial full process snapshot
- `--once` — Take one snapshot and exit

### 4. Start the frontend
```bash
pnpm --filter @workspace/argus run dev
```
The frontend starts on port 5173 and proxies `/api` requests to port 5000.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/events/process` | Ingest one or more process events |
| `GET` | `/api/events/process` | Retrieve recent process events |
| `GET` | `/api/events/process/stream` | SSE stream for real-time events |
| `POST` | `/api/processes` | Ingest a full process snapshot |
| `GET` | `/api/processes` | Retrieve current process snapshot |

## Event Model

```json
{
  "id": "uuid",
  "event_type": "PROCESS_STARTED | PROCESS_TERMINATED | SNAPSHOT",
  "timestamp": "2026-09-08T12:00:00Z",
  "pid": 1234,
  "process_name": "notepad.exe",
  "executable_path": "C:\\Windows\\System32\\notepad.exe",
  "parent_pid": 500,
  "parent_process_name": "explorer.exe",
  "source": "windows_process_monitor",
  "observed": true,
  "metadata": {
    "cpu_percent": 1.2,
    "memory_bytes": 12345678,
    "username": "DOMAIN\\user"
  }
}
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PROCESS_POLL_INTERVAL_MS` | `2000` | Polling interval in milliseconds |
| `ARGUS_API_BASE_URL` | `http://localhost:5000` | API server base URL |
| `ARGUS_LOG_LEVEL` | `INFO` | Python log level |
| `PORT` (API) | `5000` | API server port |
| `ARGUS_API_URL` (Vite) | `http://localhost:5000` | API URL for Vite proxy |

## What is REAL vs DEMO

### REAL (when engine is running)
- Windows process enumeration via psutil
- Process creation detection
- Process termination detection
- Parent-child relationships
- CPU/memory usage per process
- Process executable paths
- User/context information
- Access error handling (AccessDenied)

### DEMO (always available, clearly labeled)
- Threat detections (synthetic scenario)
- File activity telemetry
- Network connection analysis
- Exposure assessment scores
- Incident timeline events
- Quarantine actions
- Cyber Cell submissions
- All navigation and UI functionality

The Processes page shows a clear **"REAL WINDOWS TELEMETRY"** badge when live data is available, or **"DEMO DATA"** when showing synthetic data. An offline banner appears when the security engine is not connected.

## Limitations

1. **No file monitoring** — Phase 2
2. **No network monitoring** — Phase 2
3. **No malware detection** — Phase 2
4. **No automatic quarantine** — Phase 2
5. **No database persistence** — Events stored in-memory; schema prepared for future use
6. **No authentication on API** — Phase 2+
7. **Polling-based** — Uses 2-second polling; not event-driven via ETW/WMI
8. **Windows-only** — psutil works cross-platform but tested on Windows
9. **No executable signature verification** — Would require additional libraries

## Permissions

- The process monitor runs as the current user
- Some system processes (System, Registry, etc.) will return AccessDenied for executable paths
- The monitor does NOT require administrator privileges
- The monitor does NOT terminate, suspend, or modify any processes
- The monitor does NOT collect credentials, passwords, cookies, or private content

## Known Windows Access Restrictions

| Process Type | Typical Access |
|-------------|---------------|
| User processes | Full access to name, PID, parent, CPU, memory |
| System processes (System, Registry) | Name and PID accessible, exe path may be denied |
| Protected processes (lsass.exe, csrss.exe) | Most fields return AccessDenied |
| Own process | Full access |

## Testing

Unit tests should be created for:
1. Process snapshot parsing
2. New process detection (create/kill test processes)
3. Process termination detection
4. Parent-child relationship handling
5. AccessDenied handling
6. Clean shutdown
7. API schema validation
8. SSE connection lifecycle

All tests should use mocked process data — never terminate real system processes.

## Verification Checklist

- [x] Real Windows processes can be enumerated
- [x] New process creation can be detected
- [x] Process termination can be detected
- [x] Parent-child relationships are captured where available
- [x] AccessDenied does not crash the engine
- [x] Events have timestamps
- [x] Events are normalized
- [x] API accepts validated process events
- [x] UI can display real process events
- [x] Real vs DEMO data is clearly identified
- [x] No destructive process operations exist
- [x] Typecheck passes
- [x] Build passes
- [x] Existing ARGUS navigation remains functional
- [x] Existing prototype features remain functional
- [x] Documentation exists
- [x] No credentials/private content are collected
