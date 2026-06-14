import { openDb } from "../db";
import { seed } from "../seed";

/**
 * Opens a fresh in-memory SQLite database, seeds it, and returns it.
 * Each call returns an independent database — safe to use per-test.
 */
export function openDbInMemory() {
  const db = openDb(":memory:");
  seed(db);
  return db;
}
