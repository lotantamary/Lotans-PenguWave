// Shared helpers for PenguWave.
import DOMPurify from "dompurify";

/**
 * Sanitize a string before rendering it as HTML.
 * Strips dangerous markup so values can be safely shown to the user.
 */
export function sanitizeHtml(input: string): string {
  return DOMPurify.sanitize(input);
}

/**
 * Escape a single CSV cell value.
 * - Prefixes formula-injection characters (=, +, -, @) with a single quote.
 * - Wraps in double quotes and doubles internal quotes when the value contains
 *   double quotes, commas, or newlines.
 */
function escapeCsvCell(value: string): string {
  // Formula-injection guard: prefix dangerous leading characters
  if (value.startsWith("=") || value.startsWith("+") || value.startsWith("-") || value.startsWith("@")) {
    value = "'" + value;
  }

  // Quote wrapping: if value contains double-quote, comma, or newline
  if (value.includes('"') || value.includes(",") || value.includes("\n")) {
    value = '"' + value.replace(/"/g, '""') + '"';
  }

  return value;
}

/**
 * Serialize a list of records to CSV for export.
 * Returns an empty string for empty input.
 */
export function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return "";
  const headers = Object.keys(rows[0]);
  const lines = rows.map((r) =>
    headers.map((h) => escapeCsvCell(String(r[h] ?? ""))).join(",")
  );
  return [headers.map(escapeCsvCell).join(","), ...lines].join("\n");
}
