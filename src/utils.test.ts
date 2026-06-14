// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import { sanitizeHtml, toCsv } from "./utils";

describe("sanitizeHtml", () => {
  it("strips XSS payloads from HTML", () => {
    const result = sanitizeHtml('<img src=x onerror="alert(1)">hi');
    expect(result).not.toContain("onerror");
    expect(result).not.toContain("<script");
  });

  it("preserves safe HTML content", () => {
    const result = sanitizeHtml("<b>hello</b>");
    expect(result).toContain("hello");
  });
});

describe("toCsv", () => {
  it("returns empty string for empty input", () => {
    expect(toCsv([])).toBe("");
  });

  it("prefixes formula-injection characters with single quote", () => {
    const result = toCsv([{ a: "=HYPERLINK(1)", b: "+cmd" }]);
    const lines = result.split("\n");
    // data row is lines[1]
    const dataRow = lines[1];
    expect(dataRow).toContain("'=HYPERLINK(1)");
    expect(dataRow).toContain("'+cmd");
  });

  it("prefixes - and @ formula-injection characters with single quote", () => {
    const result = toCsv([{ a: "-cmd", b: "@SUM" }]);
    const lines = result.split("\n");
    const dataRow = lines[1];
    expect(dataRow).toContain("'-cmd");
    expect(dataRow).toContain("'@SUM");
  });

  it("wraps cells containing commas in double quotes", () => {
    const result = toCsv([{ name: "x,y" }]);
    const lines = result.split("\n");
    const dataRow = lines[1];
    expect(dataRow).toContain('"x,y"');
  });

  it("wraps cells containing newlines in double quotes", () => {
    const result = toCsv([{ val: "line1\nline2" }]);
    // The whole CSV is joined by newlines but the cell should be quoted
    expect(result).toContain('"line1\nline2"');
  });

  it("doubles internal quotes when wrapping in double quotes", () => {
    const result = toCsv([{ val: 'say "hi"' }]);
    expect(result).toContain('"say ""hi"""');
  });

  it("includes header row from object keys", () => {
    const result = toCsv([{ firstName: "Alice", lastName: "Smith" }]);
    const firstLine = result.split("\n")[0];
    expect(firstLine).toBe("firstName,lastName");
  });
});
