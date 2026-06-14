/**
 * Threat scanner: inspects text fields of a raw event object and returns
 * a de-duplicated array of threat flag strings.
 */

const TEXT_FIELDS = [
  "title",
  "description",
  "assetHostname",
  "assetIp",
  "sourceIp",
  "userId",
];

/** Patterns that indicate XSS payloads */
const XSS_PATTERNS: RegExp[] = [
  /<script/i,
  /[\s/]on\w+\s*=/i,   // inline event handlers like onerror=, onclick=, <div/onclick=, etc.
  /javascript:/i,
];

/** Formula injection: trimmed value starts with one of these characters */
const FORMULA_INJECTION_CHARS = new Set(["=", "+", "-", "@"]);

function hasXss(value: string): boolean {
  return XSS_PATTERNS.some((pattern) => pattern.test(value));
}

function hasFormulaInjection(value: string): boolean {
  const trimmed = value.trimStart();
  return trimmed.length > 0 && FORMULA_INJECTION_CHARS.has(trimmed[0]);
}

/**
 * Scans the event's text fields and returns a de-duplicated array of flags.
 * Possible flags: "xss", "formula-injection".
 * Non-string / null / undefined fields are silently skipped.
 */
export function scanForThreats(event: Record<string, unknown>): string[] {
  const flags = new Set<string>();

  for (const field of TEXT_FIELDS) {
    const value = event[field];
    if (typeof value !== "string") {
      // skip null, undefined, numbers, objects, etc.
      continue;
    }

    if (hasXss(value)) {
      flags.add("xss");
    }

    if (hasFormulaInjection(value)) {
      flags.add("formula-injection");
    }
  }

  return Array.from(flags);
}
