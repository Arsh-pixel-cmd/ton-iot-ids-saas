import {
  int,
  index,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  uniqueIndex,
  varchar,
  decimal,
} from "drizzle-orm/mysql-core";

/** Core user table backing the Manus OAuth flow. */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const organizations = mysqlTable("organizations", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 160 }).notNull(),
  slug: varchar("slug", { length: 180 }).notNull().unique(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Organization = typeof organizations.$inferSelect;

export const organizationMembers = mysqlTable(
  "organization_members",
  {
    id: int("id").autoincrement().primaryKey(),
    organizationId: int("organizationId").notNull(),
    userId: int("userId").notNull(),
    role: mysqlEnum("role", ["owner", "analyst", "viewer"]).default("owner").notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  table => ({
    organizationUserUnique: uniqueIndex("organization_members_org_user_unique").on(
      table.organizationId,
      table.userId,
    ),
    userLookup: index("organization_members_user_idx").on(table.userId),
  }),
);

export type OrganizationMember = typeof organizationMembers.$inferSelect;

export const analysisRuns = mysqlTable(
  "analysis_runs",
  {
    id: int("id").autoincrement().primaryKey(),
    organizationId: int("organizationId").notNull(),
    createdByUserId: int("createdByUserId").notNull(),
    fileName: varchar("fileName", { length: 255 }).notNull(),
    modelVersion: varchar("modelVersion", { length: 120 }).notNull(),
    decisionThreshold: decimal("decisionThreshold", { precision: 5, scale: 4 }).notNull(),
    rowCount: int("rowCount").default(0).notNull(),
    attackCount: int("attackCount").default(0).notNull(),
    normalCount: int("normalCount").default(0).notNull(),
    status: mysqlEnum("status", ["completed", "failed"]).default("completed").notNull(),
    errorMessage: text("errorMessage"),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  table => ({
    organizationCreated: index("analysis_runs_org_created_idx").on(
      table.organizationId,
      table.createdAt,
    ),
  }),
);

export type AnalysisRun = typeof analysisRuns.$inferSelect;
export type InsertAnalysisRun = typeof analysisRuns.$inferInsert;

export const alerts = mysqlTable(
  "alerts",
  {
    id: int("id").autoincrement().primaryKey(),
    organizationId: int("organizationId").notNull(),
    analysisRunId: int("analysisRunId").notNull(),
    rowNumber: int("rowNumber").notNull(),
    prediction: int("prediction").notNull(),
    predictionName: mysqlEnum("predictionName", ["normal", "attack"]).notNull(),
    probabilityAttack: decimal("probabilityAttack", { precision: 8, scale: 6 }).notNull(),
    severity: mysqlEnum("severity", ["low", "medium", "high", "critical"]).notNull(),
    srcIp: varchar("srcIp", { length: 64 }),
    dstIp: varchar("dstIp", { length: 64 }),
    dstPort: int("dstPort"),
    proto: varchar("proto", { length: 32 }),
    connState: varchar("connState", { length: 32 }),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  table => ({
    runLookup: index("alerts_run_idx").on(table.analysisRunId),
    organizationCreated: index("alerts_org_created_idx").on(
      table.organizationId,
      table.createdAt,
    ),
  }),
);

export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = typeof alerts.$inferInsert;
