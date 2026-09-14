/**
 * Detections database schema.
 *
 * This schema is prepared for future PostgreSQL persistence.
 * In Phase 1, detections are stored in-memory via the EventHub.
 * To activate persistence, set DATABASE_URL and run drizzle-kit push.
 */

import { pgTable, text, integer, boolean, jsonb, timestamp, uuid, numeric } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const detectionsTable = pgTable("detections", {
  id: uuid("id").primaryKey(),
  ruleId: text("rule_id").notNull(),
  ruleName: text("rule_name").notNull(),
  title: text("title").notNull(),
  severity: text("severity").notNull(),
  confidence: numeric("confidence").notNull(),
  status: text("status").notNull().default("detected"),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
  eventTimestamp: timestamp("event_timestamp", { withTimezone: true }).notNull(),
  entity: text("entity").notNull(),
  pid: integer("pid").notNull(),
  executablePath: text("executable_path"),
  commandLine: text("command_line"),
  parentPid: integer("parent_pid"),
  parentProcessName: text("parent_process_name"),
  username: text("username"),
  hostname: text("hostname"),
  evidence: jsonb("evidence").notNull().default([]),
  explanation: text("explanation").notNull(),
  recommendedAction: text("recommended_action").notNull(),
  correlatedRules: jsonb("correlated_rules"),
  ancestry: jsonb("ancestry").notNull().default([]),
  relatedEventId: text("related_event_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertDetectionSchema = createInsertSchema(detectionsTable).omit({
  id: true,
  createdAt: true,
});

export type InsertDetection = z.infer<typeof insertDetectionSchema>;
export type DetectionRecord = typeof detectionsTable.$inferSelect;