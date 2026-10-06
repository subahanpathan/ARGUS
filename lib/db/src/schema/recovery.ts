/**
 * Impact reconstruction & recovery database schema.
 *
 * Prepared for future PostgreSQL persistence, matching `detections.ts`. While
 * `DATABASE_URL` is unset the authoritative store is the in-memory
 * `RecoveryStore`, so these tables are a durable projection of state that is
 * always derivable from real telemetry.
 *
 * Three tables, deliberately normalized:
 *
 *   recovery_incidents        one reconstructed incident per detection
 *   recovery_affected_files   one row per damaged path, with damage + attribution
 *   recovery_attempts         one row per copy attempt, with verification results
 *
 * Two design points worth stating explicitly:
 *
 *  - `attributionStrength` is a first-class column. A row whose attribution only
 *    rests on the incident time window must never be queryable as if it were
 *    proven.
 *  - `destructive` is stored on every attempt and constrained to `false`. The
 *    non-destructive guarantee should be visible in the data model, not only in
 *    application code.
 */

import { pgTable, text, integer, boolean, jsonb, timestamp, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const recoveryIncidentsTable = pgTable("recovery_incidents", {
  incidentId: text("incident_id").primaryKey(),
  detectionId: text("detection_id").notNull(),
  ruleId: text("rule_id").notNull(),
  ruleName: text("rule_name").notNull(),
  severity: text("severity").notNull(),
  hostname: text("hostname"),

  /** Detection time that anchors the impact window. */
  anchorAt: timestamp("anchor_at", { withTimezone: true }).notNull(),
  windowStart: timestamp("window_start", { withTimezone: true }).notNull(),
  windowEnd: timestamp("window_end", { withTimezone: true }).notNull(),
  windowPreMs: integer("window_pre_ms").notNull(),
  windowPostMs: integer("window_post_ms").notNull(),
  windowWidened: boolean("window_widened").notNull().default(false),

  pid: integer("pid"),
  processName: text("process_name"),
  executablePath: text("executable_path"),
  commandLine: text("command_line"),
  username: text("username"),
  ancestry: jsonb("ancestry").notNull().default([]),

  phase: text("phase").notNull().default("QUEUED"),
  stagesReached: jsonb("stages_reached").notNull().default([]),

  /** Counts recomputed from affected files; denormalized for cheap dashboards. */
  progressTotal: integer("progress_total").notNull().default(0),
  progressSourcesFound: integer("progress_sources_found").notNull().default(0),
  progressAttempted: integer("progress_attempted").notNull().default(0),
  progressRecovered: integer("progress_recovered").notNull().default(0),
  progressVerified: integer("progress_verified").notNull().default(0),
  progressUnrecoverable: integer("progress_unrecoverable").notNull().default(0),
  stagePercent: integer("stage_percent").notNull().default(0),

  affectedFilesTruncated: boolean("affected_files_truncated").notNull().default(false),
  skippedReason: text("skipped_reason"),
  errors: jsonb("errors").notNull().default([]),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const recoveryAffectedFilesTable = pgTable("recovery_affected_files", {
  recordId: text("record_id").primaryKey(),
  incidentId: text("incident_id")
    .notNull()
    .references(() => recoveryIncidentsTable.incidentId, { onDelete: "cascade" }),
  detectionId: text("detection_id").notNull(),

  /** Original path, exactly as observed. Never rewritten by a recovery. */
  path: text("path").notNull(),
  name: text("name").notNull(),
  operation: text("operation").notNull(),
  previousPath: text("previous_path"),

  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
  observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
  observationCount: integer("observation_count").notNull().default(1),

  pid: integer("pid"),
  processName: text("process_name"),
  ancestry: jsonb("ancestry").notNull().default([]),

  attributionBasis: text("attribution_basis").notNull(),
  /** ATTRIBUTED (exact identifier) or INFERRED (time window only). */
  attributionStrength: text("attribution_strength").notNull(),
  evidenceSource: text("evidence_source").notNull(),
  evidence: jsonb("evidence").notNull().default([]),

  previousExists: boolean("previous_exists"),
  previousSizeBytes: integer("previous_size_bytes"),
  previousModifiedAt: timestamp("previous_modified_at", { withTimezone: true }),
  previousSha256: text("previous_sha256"),

  /** null when the path could not be confirmed absent. */
  currentExists: boolean("current_exists"),
  currentSizeBytes: integer("current_size_bytes"),
  currentModifiedAt: timestamp("current_modified_at", { withTimezone: true }),
  currentSha256: text("current_sha256"),
  currentSha256SkippedReason: text("current_sha256_skipped_reason"),

  damage: text("damage").notNull(),
  damageSignals: jsonb("damage_signals").notNull().default([]),

  recoveryState: text("recovery_state").notNull().default("DISCOVERED"),
  selectedSourceId: text("selected_source_id"),
  /** Number of probed sources; real candidates live in the attempt rows. */
  sourcesFound: integer("sources_found").notNull().default(0),
  restorableSources: integer("restorable_sources").notNull().default(0),
  notes: jsonb("notes").notNull().default([]),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const recoveryAttemptsTable = pgTable("recovery_attempts", {
  attemptId: text("attempt_id").primaryKey(),
  recordId: text("record_id")
    .notNull()
    .references(() => recoveryAffectedFilesTable.recordId, { onDelete: "cascade" }),
  incidentId: text("incident_id").notNull(),

  sourceId: text("source_id").notNull(),
  sourceKind: text("source_kind").notNull(),
  sourcePath: text("source_path"),
  sourceRole: text("source_role").notNull(),
  sourceSha256: text("source_sha256"),
  sourceSizeBytes: integer("source_size_bytes"),
  sourcePredatesWindow: boolean("source_predates_window").notNull().default(false),

  startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  outcome: text("outcome").notNull(),

  /** Always inside the ARGUS recovery workspace; never the original path. */
  recoveredPath: text("recovered_path"),
  recoveredSizeBytes: integer("recovered_size_bytes"),
  recoveredSha256: text("recovered_sha256"),

  /** True only when every required check passed. */
  verified: boolean("verified").notNull().default(false),
  checks: jsonb("checks").notNull().default([]),
  error: text("error"),
  durationMs: real("duration_ms"),

  /**
   * Structural guarantee. This phase never writes to an affected original, and
   * the column makes that auditable rather than merely documented.
   */
  destructive: boolean("destructive").notNull().default(false),
});

export const insertRecoveryIncidentSchema = createInsertSchema(recoveryIncidentsTable).omit({
  createdAt: true,
  updatedAt: true,
});

export const insertRecoveryAffectedFileSchema = createInsertSchema(recoveryAffectedFilesTable).omit({
  createdAt: true,
  updatedAt: true,
});

export const insertRecoveryAttemptSchema = createInsertSchema(recoveryAttemptsTable).omit({});

/**
 * Narrows the freely-typed `outcome` column to the two real outcomes.
 *
 * Mirrors the runtime union: a recovery attempt either produced a staged copy
 * or it did not.
 */
export const recoveryAttemptOutcomeSchema = z.enum(["SUCCEEDED", "FAILED"]);

export type InsertRecoveryIncident = z.infer<typeof insertRecoveryIncidentSchema>;
export type InsertRecoveryAffectedFile = z.infer<typeof insertRecoveryAffectedFileSchema>;
export type InsertRecoveryAttempt = z.infer<typeof insertRecoveryAttemptSchema>;
export type RecoveryAttemptOutcome = z.infer<typeof recoveryAttemptOutcomeSchema>;
export type RecoveryIncidentRecord = typeof recoveryIncidentsTable.$inferSelect;
export type RecoveryAffectedFileRecord = typeof recoveryAffectedFilesTable.$inferSelect;
export type RecoveryAttemptRecord = typeof recoveryAttemptsTable.$inferSelect;
