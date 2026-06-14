import fs from "fs";
import path from "path";
import bcrypt from "bcryptjs";
import type { Database } from "./db";
import { scanForThreats } from "./threat";

const BCRYPT_COST = 10;

interface UserSeed {
  id: string;
  email: string;
  role: string;
  status: string;
  password: string;
}

function getUsers(): UserSeed[] {
  return [
    {
      id: "usr-001",
      email: "admin@penguwave.io",
      role: "admin",
      status: "active",
      password: process.env.SEED_ADMIN_PW ?? "admin-demo-pw",
    },
    {
      id: "usr-002",
      email: "analyst@penguwave.io",
      role: "analyst",
      status: "active",
      password: process.env.SEED_ANALYST_PW ?? "analyst-demo-pw",
    },
    {
      id: "usr-003",
      email: "viewer@penguwave.io",
      role: "viewer",
      status: "disabled",
      password: process.env.SEED_VIEWER_PW ?? "viewer-demo-pw",
    },
  ];
}

function loadEvents(): Record<string, unknown>[] {
  // Avoid JSON import assertion issues across tsx/vitest by using readFileSync.
  const eventsPath = path.resolve(
    // import.meta.dirname is the directory of this file (server/)
    import.meta.dirname,
    "..",
    "data",
    "mock_events.json"
  );
  const raw = fs.readFileSync(eventsPath, "utf-8");
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error("mock_events.json is not an array");
  }
  return parsed as Record<string, unknown>[];
}

function toStringOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return value;
  return String(value);
}

/**
 * Seeds users and events into the database.
 * Idempotent — can be called multiple times without duplicating rows.
 */
export function seed(db: InstanceType<typeof Database>): void {
  const insertUser = db.prepare<{
    id: string;
    email: string;
    role: string;
    status: string;
    password_hash: string;
  }>(`
    INSERT OR IGNORE INTO users (id, email, role, status, password_hash)
    VALUES (@id, @email, @role, @status, @password_hash)
  `);

  const insertEvent = db.prepare<{
    id: string;
    timestamp: string | null;
    severity: string | null;
    title: string | null;
    description: string | null;
    assetHostname: string | null;
    assetIp: string | null;
    sourceIp: string | null;
    tags: string;
    userId: string | null;
    threatFlags: string;
  }>(`
    INSERT OR IGNORE INTO events
      (id, timestamp, severity, title, description, assetHostname, assetIp, sourceIp, tags, userId, threatFlags)
    VALUES
      (@id, @timestamp, @severity, @title, @description, @assetHostname, @assetIp, @sourceIp, @tags, @userId, @threatFlags)
  `);

  // Seed users and events in a single transaction for correctness and speed
  db.transaction(() => {
    for (const user of getUsers()) {
      const password_hash = bcrypt.hashSync(user.password, BCRYPT_COST);
      insertUser.run({
        id: user.id,
        email: user.email,
        role: user.role,
        status: user.status,
        password_hash,
      });
    }

    const events = loadEvents();
    for (const event of events) {
      // Skip records with no valid string id
      if (typeof event.id !== "string" || event.id.trim() === "") {
        continue;
      }

      const tags = Array.isArray(event.tags)
        ? JSON.stringify(event.tags)
        : "[]";

      const threatFlags = JSON.stringify(scanForThreats(event));

      insertEvent.run({
        id: event.id,
        timestamp: toStringOrNull(event.timestamp),
        severity: toStringOrNull(event.severity),
        title: toStringOrNull(event.title),
        description: toStringOrNull(event.description),
        assetHostname: toStringOrNull(event.assetHostname),
        assetIp: toStringOrNull(event.assetIp),
        sourceIp: toStringOrNull(event.sourceIp),
        tags,
        userId: toStringOrNull(event.userId),
        threatFlags,
      });
    }
  })();
}
