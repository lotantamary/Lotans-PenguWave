import Database from "better-sqlite3";

export type { Database };

/**
 * Creates (or reuses) the tables required by PenguWave.
 */
export function initSchema(db: InstanceType<typeof Database>): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      email         TEXT UNIQUE NOT NULL,
      role          TEXT NOT NULL,
      status        TEXT NOT NULL,
      password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
      id            TEXT PRIMARY KEY,
      timestamp     TEXT,
      severity      TEXT,
      title         TEXT,
      description   TEXT,
      assetHostname TEXT,
      assetIp       TEXT,
      sourceIp      TEXT,
      tags          TEXT NOT NULL DEFAULT '[]',
      userId        TEXT,
      threatFlags   TEXT NOT NULL DEFAULT '[]'
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
}

/**
 * Opens a better-sqlite3 database, configures WAL mode and foreign keys,
 * initialises the schema, and returns the db instance.
 */
export function openDb(path = "penguwave.db"): InstanceType<typeof Database> {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  initSchema(db);
  return db;
}
