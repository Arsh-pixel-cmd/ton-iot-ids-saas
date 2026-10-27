import { desc, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  Alert,
  alerts,
  AnalysisRun,
  analysisRuns,
  InsertAlert,
  InsertAnalysisRun,
  InsertUser,
  Organization,
  organizationMembers,
  organizations,
  users,
} from "../drizzle/schema";
import { ENV } from "./env";

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

const inMemoryOrg: Organization = {
  id: 1,
  name: "Security workspace",
  slug: "workspace-1",
  createdAt: new Date(),
  updatedAt: new Date(),
};

let inMemoryRunId = 1;
const inMemoryRuns: AnalysisRun[] = [];

let inMemoryAlertId = 1;
const inMemoryAlerts: Alert[] = [];

export async function getOrCreateOrganizationForUser(userId: number, userName?: string | null): Promise<Organization> {
  const db = await getDb();
  if (!db) {
    return inMemoryOrg;
  }

  const membership = await db
    .select({ organization: organizations })
    .from(organizationMembers)
    .innerJoin(organizations, eq(organizationMembers.organizationId, organizations.id))
    .where(eq(organizationMembers.userId, userId))
    .limit(1);

  if (membership[0]?.organization) return membership[0].organization;

  const baseName = userName?.trim() ? `${userName.trim()}'s workspace` : "Security workspace";
  const slug = `workspace-${userId}`;
  await db.insert(organizations).values({ name: baseName, slug });

  const created = await db
    .select()
    .from(organizations)
    .where(eq(organizations.slug, slug))
    .limit(1);
  const organization = created[0];
  if (!organization) throw new Error("Unable to create organization");

  await db.insert(organizationMembers).values({
    organizationId: organization.id,
    userId,
    role: "owner",
  });

  return organization;
}

export async function getOrganizationForUser(userId: number) {
  const db = await getDb();
  if (!db) {
    return { organization: inMemoryOrg, role: "owner" as const };
  }

  const result = await db
    .select({ organization: organizations, role: organizationMembers.role })
    .from(organizationMembers)
    .innerJoin(organizations, eq(organizationMembers.organizationId, organizations.id))
    .where(eq(organizationMembers.userId, userId))
    .limit(1);

  return result[0];
}

export async function createAnalysisRun(run: InsertAnalysisRun): Promise<AnalysisRun | undefined> {
  const db = await getDb();
  if (!db) {
    const created: AnalysisRun = {
      id: inMemoryRunId++,
      organizationId: run.organizationId,
      createdByUserId: run.createdByUserId,
      fileName: run.fileName,
      modelVersion: run.modelVersion,
      decisionThreshold: String(run.decisionThreshold),
      rowCount: run.rowCount ?? 0,
      attackCount: run.attackCount ?? 0,
      normalCount: run.normalCount ?? 0,
      status: run.status ?? "completed",
      errorMessage: run.errorMessage ?? null,
      createdAt: new Date(),
    };
    inMemoryRuns.unshift(created);
    return created;
  }

  await db.insert(analysisRuns).values(run);
  const created = await db
    .select()
    .from(analysisRuns)
    .where(eq(analysisRuns.organizationId, run.organizationId))
    .orderBy(desc(analysisRuns.id))
    .limit(1);
  return created[0];
}

export async function insertAlerts(items: InsertAlert[]) {
  if (items.length === 0) return;
  const db = await getDb();
  if (!db) {
    for (const item of items) {
      const alert: Alert = {
        id: inMemoryAlertId++,
        organizationId: item.organizationId,
        analysisRunId: item.analysisRunId,
        rowNumber: item.rowNumber,
        prediction: item.prediction,
        predictionName: item.predictionName,
        probabilityAttack: String(item.probabilityAttack),
        severity: item.severity,
        srcIp: item.srcIp ?? null,
        dstIp: item.dstIp ?? null,
        dstPort: item.dstPort ?? null,
        proto: item.proto ?? null,
        connState: item.connState ?? null,
        createdAt: new Date(),
      };
      inMemoryAlerts.unshift(alert);
    }
    return;
  }
  await db.insert(alerts).values(items);
}

export async function listAnalysisRuns(organizationId: number, limit = 12): Promise<AnalysisRun[]> {
  const db = await getDb();
  if (!db) return inMemoryRuns.slice(0, limit);
  return db
    .select()
    .from(analysisRuns)
    .where(eq(analysisRuns.organizationId, organizationId))
    .orderBy(desc(analysisRuns.createdAt))
    .limit(limit);
}

export async function listAlerts(organizationId: number, limit = 50): Promise<Alert[]> {
  const db = await getDb();
  if (!db) return inMemoryAlerts.slice(0, limit);
  return db
    .select()
    .from(alerts)
    .where(eq(alerts.organizationId, organizationId))
    .orderBy(desc(alerts.createdAt))
    .limit(limit);
}
