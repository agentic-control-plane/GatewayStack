import { describe, it, expect } from "vitest";
import {
  assertUrlSafe,
  sanitizeHeaderValue,
  extractIpv4MappedIpv6,
} from "../src/security.js";

// Default resolver injected in every test so we never hit real DNS.
// Individual tests override this when they want to exercise the DNS path.
const publicResolver = async (_host: string) => [
  { address: "93.184.216.34", family: 4 as 4 | 6 },
];

describe("assertUrlSafe — protocol", () => {
  it("allows HTTPS", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://api.example.com/data"),
        allowedHosts: ["api.example.com"],
        resolve: publicResolver,
      })
    ).resolves.toBeUndefined();
  });

  it("blocks HTTP by default", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("http://api.example.com/"),
        allowedHosts: ["api.example.com"],
        resolve: publicResolver,
      })
    ).rejects.toThrow("Blocked protocol");
  });

  it("allows HTTP when allowHttp is true", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("http://api.example.com/"),
        allowedHosts: ["api.example.com"],
        allowHttp: true,
        resolve: publicResolver,
      })
    ).resolves.toBeUndefined();
  });

  it("blocks non-http/https protocols", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("ftp://api.example.com/"),
        allowedHosts: ["api.example.com"],
        resolve: publicResolver,
      })
    ).rejects.toThrow("Blocked protocol");
  });
});

describe("assertUrlSafe — allowedHosts", () => {
  it("blocks host not in allowedHosts", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://evil.com/"),
        allowedHosts: ["api.example.com"],
        resolve: publicResolver,
      })
    ).rejects.toThrow("Blocked host");
  });

  it("is case-insensitive for host matching", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://API.Example.COM/"),
        allowedHosts: ["api.example.com"],
        resolve: publicResolver,
      })
    ).resolves.toBeUndefined();
  });

  it("accepts any of multiple hosts", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://api2.example.com/"),
        allowedHosts: ["api1.example.com", "api2.example.com"],
        resolve: publicResolver,
      })
    ).resolves.toBeUndefined();
  });
});

describe("assertUrlSafe — private IP literals", () => {
  const ranges: Array<[string, string]> = [
    ["127.0.0.1", "loopback"],
    ["10.0.0.1", "10/8"],
    ["192.168.1.1", "192.168/16"],
    ["172.16.0.1", "172.16/12"],
    ["172.31.255.255", "172.16/12 upper"],
    ["169.254.169.254", "cloud metadata"],
    ["0.0.0.0", "this network"],
  ];

  for (const [ip, label] of ranges) {
    it(`blocks ${ip} (${label})`, async () => {
      await expect(
        assertUrlSafe({
          url: new URL(`https://${ip}/`),
          allowedHosts: [ip],
          resolve: publicResolver,
        })
      ).rejects.toThrow("Blocked private IPv4");
    });
  }

  it("allows private IPs when allowPrivateIps is true", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://127.0.0.1/"),
        allowedHosts: ["127.0.0.1"],
        allowPrivateIps: true,
        resolve: publicResolver,
      })
    ).resolves.toBeUndefined();
  });
});

describe("assertUrlSafe — IPv6 literals", () => {
  it("blocks ::1 loopback", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://[::1]/"),
        allowedHosts: ["::1"],
        resolve: publicResolver,
      })
    ).rejects.toThrow("Blocked private IPv6");
  });

  it("blocks fc00::/7 unique local", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://[fc00::1]/"),
        allowedHosts: ["fc00::1"],
        resolve: publicResolver,
      })
    ).rejects.toThrow("Blocked private IPv6");
  });

  it("blocks fe80::/10 link-local", async () => {
    await expect(
      assertUrlSafe({
        url: new URL("https://[fe80::1]/"),
        allowedHosts: ["fe80::1"],
        resolve: publicResolver,
      })
    ).rejects.toThrow("Blocked private IPv6");
  });

  it("blocks IPv4-mapped IPv6 pointing to private v4 (::ffff:127.0.0.1)", async () => {
    // Node canonicalizes ::ffff:127.0.0.1 to the compressed form
    // ::ffff:7f00:1 on the URL's hostname, so an operator configuring
    // this allowlist entry needs to use the canonical form too.
    const url = new URL("https://[::ffff:127.0.0.1]/");
    await expect(
      assertUrlSafe({
        url,
        allowedHosts: [url.hostname.replace(/^\[|\]$/g, "")],
        resolve: publicResolver,
      })
    ).rejects.toThrow("IPv4-mapped IPv6 private");
  });
});

describe("assertUrlSafe — DNS resolution (rebinding defense)", () => {
  it("blocks when allowlisted hostname resolves to a private IP", async () => {
    const rebindResolver = async () => [
      { address: "127.0.0.1", family: 4 as 4 | 6 },
    ];
    await expect(
      assertUrlSafe({
        url: new URL("https://api.example.com/"),
        allowedHosts: ["api.example.com"],
        resolve: rebindResolver,
      })
    ).rejects.toThrow("resolved address for api.example.com");
  });

  it("blocks when ANY resolved address is private (mixed results)", async () => {
    const mixedResolver = async () => [
      { address: "93.184.216.34", family: 4 as 4 | 6 },
      { address: "10.0.0.5", family: 4 as 4 | 6 },
    ];
    await expect(
      assertUrlSafe({
        url: new URL("https://api.example.com/"),
        allowedHosts: ["api.example.com"],
        resolve: mixedResolver,
      })
    ).rejects.toThrow("Blocked private IPv4");
  });

  it("blocks when resolved IPv6 is private", async () => {
    const v6Resolver = async () => [
      { address: "::1", family: 6 as 4 | 6 },
    ];
    await expect(
      assertUrlSafe({
        url: new URL("https://api.example.com/"),
        allowedHosts: ["api.example.com"],
        resolve: v6Resolver,
      })
    ).rejects.toThrow("Blocked private IPv6");
  });

  it("blocks when resolved IPv4-mapped IPv6 embeds a private v4", async () => {
    const mappedResolver = async () => [
      { address: "::ffff:169.254.169.254", family: 6 as 4 | 6 },
    ];
    await expect(
      assertUrlSafe({
        url: new URL("https://meta.example.com/"),
        allowedHosts: ["meta.example.com"],
        resolve: mappedResolver,
      })
    ).rejects.toThrow("IPv4-mapped IPv6 private");
  });

  it("allows when all resolved addresses are public", async () => {
    const publicV6Resolver = async () => [
      { address: "2606:4700:4700::1111", family: 6 as 4 | 6 },
      { address: "1.1.1.1", family: 4 as 4 | 6 },
    ];
    await expect(
      assertUrlSafe({
        url: new URL("https://one.example.com/"),
        allowedHosts: ["one.example.com"],
        resolve: publicV6Resolver,
      })
    ).resolves.toBeUndefined();
  });

  it("does not call the resolver when allowPrivateIps is true", async () => {
    let called = false;
    const spyResolver = async () => {
      called = true;
      return [{ address: "127.0.0.1", family: 4 as 4 | 6 }];
    };
    await assertUrlSafe({
      url: new URL("https://internal.example.com/"),
      allowedHosts: ["internal.example.com"],
      allowPrivateIps: true,
      resolve: spyResolver,
    });
    expect(called).toBe(false);
  });
});

describe("extractIpv4MappedIpv6", () => {
  it("extracts the embedded v4 from a mapped v6", () => {
    expect(extractIpv4MappedIpv6("::ffff:127.0.0.1")).toBe("127.0.0.1");
  });

  it("is case-insensitive on the ffff token", () => {
    expect(extractIpv4MappedIpv6("::FFFF:10.0.0.1")).toBe("10.0.0.1");
  });

  it("handles Node's canonical compressed hex form (::ffff:7f00:1 → 127.0.0.1)", () => {
    expect(extractIpv4MappedIpv6("::ffff:7f00:1")).toBe("127.0.0.1");
  });

  it("handles the hex form for cloud metadata (::ffff:a9fe:a9fe → 169.254.169.254)", () => {
    expect(extractIpv4MappedIpv6("::ffff:a9fe:a9fe")).toBe("169.254.169.254");
  });

  it("returns null for plain IPv6", () => {
    expect(extractIpv4MappedIpv6("::1")).toBeNull();
    expect(extractIpv4MappedIpv6("fe80::1")).toBeNull();
  });

  it("returns null for non-mapped addresses", () => {
    expect(extractIpv4MappedIpv6("2606:4700::1111")).toBeNull();
  });
});

describe("sanitizeHeaderValue", () => {
  it("strips CRLF characters", () => {
    expect(sanitizeHeaderValue("value\r\ninjected")).toBe("value injected");
  });

  it("trims whitespace", () => {
    expect(sanitizeHeaderValue("  value  ")).toBe("value");
  });

  it("handles clean values", () => {
    expect(sanitizeHeaderValue("Bearer abc123")).toBe("Bearer abc123");
  });
});
