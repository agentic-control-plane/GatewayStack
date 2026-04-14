import { describe, it, expect } from "vitest";
import { detectPii } from "../src/detect.js";

describe("detectPii", () => {
  describe("email", () => {
    it("detects simple email", () => {
      const matches = detectPii("contact john@example.com for info");
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe("email");
      expect(matches[0].value).toBe("john@example.com");
    });

    it("detects multiple emails", () => {
      const matches = detectPii("a@b.com and c@d.org");
      const emails = matches.filter((m) => m.type === "email");
      expect(emails).toHaveLength(2);
    });

    it("detects email with plus addressing", () => {
      const matches = detectPii("user+tag@example.com");
      expect(matches.some((m) => m.type === "email")).toBe(true);
    });
  });

  describe("phone", () => {
    it("detects US phone with area code and dashes", () => {
      const matches = detectPii("call 555-123-4567 now");
      const phones = matches.filter((m) => m.type === "phone");
      expect(phones).toHaveLength(1);
      expect(phones[0].value).toContain("555");
    });

    it("detects phone with parentheses", () => {
      const matches = detectPii("call (555) 123-4567");
      const phones = matches.filter((m) => m.type === "phone");
      expect(phones).toHaveLength(1);
    });

    it("detects phone with +1 prefix", () => {
      const matches = detectPii("call +1-555-123-4567");
      const phones = matches.filter((m) => m.type === "phone");
      expect(phones).toHaveLength(1);
    });

    it("does NOT match 7-digit numbers without area code", () => {
      const matches = detectPii("number 1234567 in text");
      const phones = matches.filter((m) => m.type === "phone");
      expect(phones).toHaveLength(0);
    });
  });

  describe("ssn", () => {
    it("detects SSN format", () => {
      const matches = detectPii("SSN: 123-45-6789");
      const ssns = matches.filter((m) => m.type === "ssn");
      expect(ssns).toHaveLength(1);
      expect(ssns[0].value).toBe("123-45-6789");
    });

    it("does not match partial SSN", () => {
      const matches = detectPii("code 12-34-5678");
      const ssns = matches.filter((m) => m.type === "ssn");
      expect(ssns).toHaveLength(0);
    });
  });

  describe("credit_card", () => {
    it("detects Visa 16-digit", () => {
      const matches = detectPii("card: 4111 1111 1111 1111");
      const cards = matches.filter((m) => m.type === "credit_card");
      expect(cards).toHaveLength(1);
    });

    it("detects Mastercard", () => {
      const matches = detectPii("card: 5500-0000-0000-0004");
      const cards = matches.filter((m) => m.type === "credit_card");
      expect(cards).toHaveLength(1);
    });

    it("detects Amex (15 digits)", () => {
      const matches = detectPii("card: 3782 822463 10005");
      const cards = matches.filter((m) => m.type === "credit_card");
      expect(cards).toHaveLength(1);
    });

    it("detects Discover", () => {
      const matches = detectPii("card: 6011 1111 1111 1117");
      const cards = matches.filter((m) => m.type === "credit_card");
      expect(cards).toHaveLength(1);
    });
  });

  describe("ip_address", () => {
    it("detects IPv4 address", () => {
      const matches = detectPii("server at 192.168.1.1 is up");
      const ips = matches.filter((m) => m.type === "ip_address");
      expect(ips).toHaveLength(1);
      expect(ips[0].value).toBe("192.168.1.1");
    });

    it("does not match invalid octets", () => {
      const matches = detectPii("value 999.999.999.999");
      const ips = matches.filter((m) => m.type === "ip_address");
      expect(ips).toHaveLength(0);
    });
  });

  describe("date_of_birth", () => {
    it("detects MM/DD/YYYY", () => {
      const matches = detectPii("DOB: 01/15/1990");
      const dobs = matches.filter((m) => m.type === "date_of_birth");
      expect(dobs).toHaveLength(1);
    });

    it("detects YYYY-MM-DD", () => {
      const matches = detectPii("born 1990-01-15");
      const dobs = matches.filter((m) => m.type === "date_of_birth");
      expect(dobs).toHaveLength(1);
    });
  });

  describe("mixed content", () => {
    it("detects multiple PII types in one string", () => {
      const text = "Email john@test.com, SSN 123-45-6789, IP 10.0.0.1";
      const matches = detectPii(text);
      const types = new Set(matches.map((m) => m.type));
      expect(types.has("email")).toBe(true);
      expect(types.has("ssn")).toBe(true);
      expect(types.has("ip_address")).toBe(true);
    });

    it("returns matches sorted by position", () => {
      const text = "SSN 123-45-6789 and email a@b.com";
      const matches = detectPii(text);
      for (let i = 1; i < matches.length; i++) {
        expect(matches[i].start).toBeGreaterThanOrEqual(matches[i - 1].start);
      }
    });
  });

  describe("no PII", () => {
    it("returns empty array for clean text", () => {
      const matches = detectPii("This is a perfectly normal sentence.");
      expect(matches).toHaveLength(0);
    });
  });

  describe("zero-width character bypass", () => {
    it("detects email with zero-width space inside", () => {
      const text = "contact john\u200B@example.com for info";
      const matches = detectPii(text);
      const emails = matches.filter((m) => m.type === "email");
      expect(emails).toHaveLength(1);
    });

    it("detects SSN with zero-width joiner inside", () => {
      const text = "ssn is 123-\u200D45-6789";
      const matches = detectPii(text);
      const ssns = matches.filter((m) => m.type === "ssn");
      expect(ssns).toHaveLength(1);
    });

    it("reports match offsets in the ORIGINAL text so redaction covers ZW chars", () => {
      const text = "contact john\u200B@example.com for info";
      const [m] = detectPii(text);
      // The original substring between start and end must include the ZW
      // char; redaction slices text[start:end], so this is what gets removed.
      expect(text.slice(m.start, m.end)).toBe("john\u200B@example.com");
    });

    it("value field preserves the original obfuscated form", () => {
      const text = "contact john\u200B@example.com";
      const [m] = detectPii(text);
      expect(m.value).toBe("john\u200B@example.com");
    });

    it("clean text is unaffected (fast-path parity)", () => {
      const text = "contact john@example.com";
      const [m] = detectPii(text);
      expect(m.start).toBe(8);
      expect(m.end).toBe(24);
      expect(m.value).toBe("john@example.com");
    });
  });
});
