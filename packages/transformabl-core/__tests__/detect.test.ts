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

  // ─────────────────────────────────────────────────────────────────────
  // Presidio-parity recognizers (v0.4.0)
  // ─────────────────────────────────────────────────────────────────────

  describe("us_bank_number", () => {
    it("detects 10-digit bank account", () => {
      const matches = detectPii("account 9845302145 for deposit");
      expect(matches.some((m) => m.type === "us_bank_number")).toBe(true);
    });

    it("detects 17-digit routing/account combos", () => {
      const matches = detectPii("wire to 12345678901234567");
      expect(matches.some((m) => m.type === "us_bank_number")).toBe(true);
    });

    it("does NOT match 7-digit values (too short)", () => {
      const matches = detectPii("code 1234567");
      expect(matches.some((m) => m.type === "us_bank_number")).toBe(false);
    });
  });

  describe("us_itin", () => {
    it("detects ITIN format 9XX-7X-XXXX", () => {
      const matches = detectPii("ITIN: 912-78-5551");
      expect(matches.some((m) => m.type === "us_itin")).toBe(true);
    });

    it("detects ITIN format 9XX-8X-XXXX", () => {
      const matches = detectPii("taxpayer 988-83-0099");
      expect(matches.some((m) => m.type === "us_itin")).toBe(true);
    });

    it("regular SSN 123-45-6789 does not match ITIN pattern", () => {
      const matches = detectPii("ssn 123-45-6789");
      expect(matches.some((m) => m.type === "us_itin")).toBe(false);
    });
  });

  describe("us_passport", () => {
    it("detects 9-digit passport", () => {
      const matches = detectPii("passport 123456789 expires");
      expect(matches.some((m) => m.type === "us_passport")).toBe(true);
    });

    it("detects 1-letter + 8-digit format", () => {
      const matches = detectPii("passport A12345678");
      expect(matches.some((m) => m.type === "us_passport")).toBe(true);
    });
  });

  describe("us_drivers_license", () => {
    it("detects 1-letter + 7-digit DL", () => {
      const matches = detectPii("DL D1234567 state CA");
      expect(matches.some((m) => m.type === "us_drivers_license")).toBe(true);
    });

    it("detects DL: prefix form", () => {
      const matches = detectPii("license DL:12345678");
      expect(matches.some((m) => m.type === "us_drivers_license")).toBe(true);
    });
  });

  describe("iban", () => {
    it("detects German IBAN", () => {
      const matches = detectPii("wire to DE89370400440532013000");
      expect(matches.some((m) => m.type === "iban")).toBe(true);
    });

    it("detects UK IBAN", () => {
      const matches = detectPii("acct GB82WEST12345698765432");
      expect(matches.some((m) => m.type === "iban")).toBe(true);
    });

    it("does NOT match arbitrary long alphanum", () => {
      const matches = detectPii("token ABCDEFGHIJKLMNOP12345");
      expect(matches.some((m) => m.type === "iban")).toBe(false);
    });
  });

  describe("phone (international)", () => {
    it("detects +44 UK number", () => {
      const matches = detectPii("call +44 20 7946 0958");
      expect(matches.some((m) => m.type === "phone")).toBe(true);
    });

    it("detects +81 Japan number", () => {
      const matches = detectPii("support +81-3-1234-5678");
      expect(matches.some((m) => m.type === "phone")).toBe(true);
    });
  });

  describe("ip_address (IPv6)", () => {
    it("detects full-form IPv6", () => {
      const matches = detectPii("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
      expect(matches.some((m) => m.type === "ip_address")).toBe(true);
    });

    it("detects compressed IPv6", () => {
      const matches = detectPii("addr 2001:db8::8a2e:370:7334");
      expect(matches.some((m) => m.type === "ip_address")).toBe(true);
    });
  });

  describe("icd_10", () => {
    it("detects F32.9 (major depressive disorder)", () => {
      const matches = detectPii("diagnosis code F32.9 confirmed");
      expect(matches.some((m) => m.type === "icd_10")).toBe(true);
    });

    it("detects E11.65 (type 2 diabetes)", () => {
      const matches = detectPii("pt has E11.65 on chart");
      expect(matches.some((m) => m.type === "icd_10")).toBe(true);
    });

    it("detects code without decimals", () => {
      const matches = detectPii("dx: Z00 routine");
      expect(matches.some((m) => m.type === "icd_10")).toBe(true);
    });
  });

  describe("icd_9", () => {
    it("detects numeric ICD-9 with decimal", () => {
      const matches = detectPii("legacy code 250.01 on record");
      expect(matches.some((m) => m.type === "icd_9")).toBe(true);
    });

    it("detects V-code", () => {
      const matches = detectPii("status V70.0");
      expect(matches.some((m) => m.type === "icd_9")).toBe(true);
    });
  });

  describe("npi", () => {
    it("detects 10-digit NPI starting with 1", () => {
      const matches = detectPii("provider NPI 1234567893 treating");
      expect(matches.some((m) => m.type === "npi")).toBe(true);
    });
  });

  describe("crypto_wallet", () => {
    it("detects BTC legacy address", () => {
      const matches = detectPii("send to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
      expect(matches.some((m) => m.type === "crypto_wallet")).toBe(true);
    });

    it("detects BTC bech32 address", () => {
      const matches = detectPii("payout bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
      expect(matches.some((m) => m.type === "crypto_wallet")).toBe(true);
    });

    it("detects ETH address", () => {
      const matches = detectPii("eth 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7");
      expect(matches.some((m) => m.type === "crypto_wallet")).toBe(true);
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
