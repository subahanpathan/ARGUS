/**
 * Process events database schema.
 *
 * This schema is prepared for future PostgreSQL persistence.
 * In Phase 1, events are stored in-memory via the EventHub.
 * To activate persistence, set DATABASE_URL and run drizzle-kit push.
 */

import { pgTable, text, integer, boolean, jsonb, timestamp, uuid } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const processEventsTable = pgTable("process_events", {
  id: uuid("id").primaryKey(),
  eventType: text("event_type").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
  pid: integer("pid").notNull(),
  processName: text("process_name").notNull(),
  executablePath: text("executable_path"),
  parentPid: integer("parent_pid"),
  parentProcessName: text("parent_process_name"),
  source: text("source").notNull().default("windows_process_monitor"),
  observed: boolean("observed").notNull().default(true),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertProcessEventSchema = createInsertSchema(processEventsTable).omit({
  id: true,
  createdAt: true,
});

export type InsertProcessEvent = z.infer<typeof insertProcessEventSchema>;
export type ProcessEventRecord = typeof processEventsTable.$inferSelect;
