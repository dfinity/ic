import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchManifest } from "../manifest.js";
import type { WebMCPManifest } from "../types.js";

const VALID_MANIFEST: WebMCPManifest = {
  schema_version: "1.0",
  canister: {
    id: "ryjl3-tyaaa-aaaaa-aaaba-cai",
    name: "Test Canister",
    description: "A test canister",
  },
  tools: [
    {
      name: "greet",
      description: "Say hello",
      canister_method: "greet",
      method_type: "query",
      inputSchema: { type: "object", properties: { name: { type: "string" } } },
    },
    {
      name: "set_name",
      description: "Set the name",
      canister_method: "set_name",
      method_type: "update",
      requires_auth: true,
      inputSchema: { type: "object", properties: { name: { type: "string" } } },
    },
  ],
};

function mockFetch(body: unknown, status = 200) {
  global.fetch = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("fetchManifest", () => {
  it("fetches and returns a valid manifest", async () => {
    mockFetch(VALID_MANIFEST);
    const manifest = await fetchManifest("/.well-known/webmcp.json");
    expect(manifest.schema_version).toBe("1.0");
    expect(manifest.canister.name).toBe("Test Canister");
    expect(manifest.tools).toHaveLength(2);
  });

  it("uses default URL when none provided", async () => {
    mockFetch(VALID_MANIFEST);
    await fetchManifest();
    expect(global.fetch).toHaveBeenCalledWith("/.well-known/webmcp.json");
  });

  it("throws on non-ok HTTP response", async () => {
    mockFetch({ error: "not found" }, 404);
    await expect(fetchManifest()).rejects.toThrow("404");
  });

  it("throws when schema_version is missing", async () => {
    const bad = { ...VALID_MANIFEST, schema_version: undefined };
    mockFetch(bad);
    await expect(fetchManifest()).rejects.toThrow("schema_version");
  });

  it("throws when canister info is missing", async () => {
    const bad = { ...VALID_MANIFEST, canister: undefined };
    mockFetch(bad);
    await expect(fetchManifest()).rejects.toThrow("canister info");
  });

  it("throws when tools array is empty", async () => {
    const bad = { ...VALID_MANIFEST, tools: [] };
    mockFetch(bad);
    await expect(fetchManifest()).rejects.toThrow("no tools");
  });

  it("throws when a tool has invalid method_type", async () => {
    const bad = {
      ...VALID_MANIFEST,
      tools: [{ ...VALID_MANIFEST.tools[0], method_type: "subscribe" }],
    };
    mockFetch(bad);
    await expect(fetchManifest()).rejects.toThrow("method_type");
  });

  it("throws when a tool is missing canister_method", async () => {
    const bad = {
      ...VALID_MANIFEST,
      tools: [{ ...VALID_MANIFEST.tools[0], canister_method: undefined }],
    };
    mockFetch(bad);
    await expect(fetchManifest()).rejects.toThrow("missing required fields");
  });
});
