import { Router } from "express";
import { requireAuth } from "../auth";
import { ApiError } from "../errors";

export const eventsRouter = Router();

// ── Row type from DB ──────────────────────────────────────────────────────────

interface EventRow {
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
}

interface ParsedEvent {
  id: string;
  timestamp: string | null;
  severity: string | null;
  title: string | null;
  description: string | null;
  assetHostname: string | null;
  assetIp: string | null;
  sourceIp: string | null;
  tags: unknown[];
  userId: string | null;
  threatFlags: unknown[];
}

function parseEventRow(row: EventRow): ParsedEvent {
  return {
    ...row,
    tags: JSON.parse(row.tags) as unknown[],
    threatFlags: JSON.parse(row.threatFlags) as unknown[],
  };
}

const EVENT_COLUMNS =
  "id, timestamp, severity, title, description, assetHostname, assetIp, sourceIp, tags, userId, threatFlags";

// Both routes require authentication
eventsRouter.use(requireAuth);

// GET /api/events
eventsRouter.get("/", (req, res) => {
  const rows = req.db
    .prepare<[], EventRow>(
      `SELECT ${EVENT_COLUMNS} FROM events ORDER BY timestamp DESC`
    )
    .all();

  res.status(200).json(rows.map(parseEventRow));
});

// GET /api/events/:id
eventsRouter.get("/:id", (req, res) => {
  const row = req.db
    .prepare<[string], EventRow>(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE id = ?`
    )
    .get(req.params.id);

  if (!row) {
    throw new ApiError(404, "Event not found");
  }

  res.status(200).json(parseEventRow(row));
});
