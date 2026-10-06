/**
 * Structured observability for the automatic recovery pipeline.
 *
 * Every stage emits a stable, machine-readable event name so an operator (or a
 * test) can follow one incident end to end without scraping prose. The contract
 * is deliberately narrow:
 *
 *  - `timestamp` is always present, and `detection_id` is present on every event
 *    except the skip path, which never opens an incident.
 *  - `incident_id` is present on every event from the moment an incident exists.
 *    `RECOVERY_TRIGGERED` is emitted *before* the incident row is created, so it
 *    carries `detection_id` only; `detection_id` is the stable join key for that
 *    one event, and `incident_id` follows on every event after it.
 *  - `record_id`, `path`, `pid`, `process_name`, `source` and `result` are
 *    included whenever the stage actually knows them.
 *  - **File contents are never logged.** Only paths, sizes, hashes and verdicts.
 *    A hash is a fingerprint, not a disclosure, and is what makes an audit trail
 *    useful without copying user data into the log stream.
 */

import { logger } from "../lib/logger";

/** The recovery pipeline's event vocabulary. */
export type RecoveryEventName =
  | "RECOVERY_TRIGGERED"
  | "IMPACT_DISCOVERY_STARTED"
  | "IMPACT_FILE_DISCOVERED"
  | "RECOVERY_SOURCE_SEARCH_STARTED"
  | "RECOVERY_SOURCE_FOUND"
  | "RECOVERY_ATTEMPT_STARTED"
  | "RECOVERY_ATTEMPT_COMPLETED"
  | "RECOVERY_VERIFICATION_STARTED"
  | "RECOVERY_VERIFICATION_COMPLETED"
  | "RECOVERY_FAILED"
  | "RECOVERY_COMPLETED";

/**
 * Fields any stage may contribute. `null` means "not known at this stage" and is
 * dropped from the emitted record rather than logged as a misleading value.
 */
export type RecoveryEventFields = {
  incident_id?: string | null;
  detection_id?: string | null;
  record_id?: string | null;
  /** Affected-file path. Safe: a path is not file content. */
  path?: string | null;
  pid?: number | null;
  process_name?: string | null;
  /** Recovery source id or path, depending on the stage. */
  source?: string | null;
  source_kind?: string | null;
  /** Verdict for the stage: the outcome, count or reason code. */
  result?: string | number | boolean | null;
  /** Free-form stage detail. Must never contain file contents. */
  detail?: string | null;
  [key: string]: unknown;
};

export type RecoveryEventSink = (name: RecoveryEventName, fields: RecoveryEventFields) => void;

const sink: RecoveryEventSink = (name, fields) => {
  logger.info({ scope: "recovery", event: name, ...prune(fields) }, name);
};

/** Drop `null`/`undefined` so a stage never logs a field it does not know. */
function prune(fields: RecoveryEventFields): RecoveryEventFields {
  const out: RecoveryEventFields = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value === null || value === undefined) continue;
    out[key] = value;
  }
  return out;
}

/**
 * Override the sink. Tests use this to assert on the exact event stream without
 * scraping formatted log output. Passing `null` restores the default.
 */
export function setRecoveryEventSink(next: RecoveryEventSink | null): void {
  activeSink = next ?? sink;
}

let activeSink: RecoveryEventSink = sink;

/** Emit one structured recovery event. */
export function emitRecoveryEvent(name: RecoveryEventName, fields: RecoveryEventFields = {}): void {
  activeSink(name, { timestamp: new Date().toISOString(), ...fields });
}
