import { describe, it, expect, vi, beforeEach } from "vitest";
import type { WebMCPManifest } from "../types.js";

// vi.mock must be at module top-level so vitest can hoist it
vi.mock("@icp-sdk/core/agent", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@icp-sdk/core/agent")>();
  return {
    ...actual,
    HttpAgent: {
      ...actual.HttpAgent,
      create: vi.fn().mockResolvedValue({
        config: { identity: Promise.resolve(null) },
        query: vi.fn().mockResolvedValue({
          status: "replied",
          reply: { arg: new ArrayBuffer(0) },
        }),
        call: vi.fn().mockResolvedValue({ response: {} }),
        replaceIdentity: vi.fn(),
        fetchRootKey: vi.fn(),
      }),
    },
  };
});

// Import after mock is set up
const { ICWebMCP } = await import("../ic-webmcp.js");

// ── Shared fixtures ──────────────────────────────────────────────────

const MANIFEST: WebMCPManifest = {
  schema_version: "1.0",
  canister: {
    id: "ryjl3-tyaaa-aaaaa-aaaba-cai",
    name: "Test Canister",
    description: "A test",
  },
  tools: [
    {
      name: "greet",
      description: "Say hello",
      canister_method: "greet",
      method_type: "query",
      inputSchema: { type: "object" },
    },
    {
      name: "transfer",
      description: "Transfer tokens",
      canister_method: "transfer",
      method_type: "update",
      requires_auth: true,
      inputSchema: { type: "object" },
    },
  ],
  authentication: {
    type: "internet-identity",
    delegation_targets: ["ryjl3-tyaaa-aaaaa-aaaba-cai"],
  },
};

function mockFetchManifest(manifest: WebMCPManifest = MANIFEST) {
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    statusText: "OK",
    json: () => Promise.resolve(manifest),
  });
}

function mockModelContext() {
  Object.defineProperty(global, "navigator", {
    value: {
      modelContext: {
        registerTool: vi.fn().mockResolvedValue(undefined),
        unregisterTool: vi.fn().mockResolvedValue(undefined),
      },
    },
    writable: true,
    configurable: true,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockFetchManifest();
  mockModelContext();
});

// ── Tests ─────────────────────────────────────────────────────────────

describe("ICWebMCP", () => {
  it("constructs with default config", () => {
    const webmcp = new ICWebMCP();
    expect(webmcp).toBeDefined();
  });

  it("constructs with custom config", () => {
    const webmcp = new ICWebMCP({
      manifestUrl: "/custom/webmcp.json",
      canisterId: "aaaaa-aa",
      host: "http://localhost:8080",
    });
    expect(webmcp).toBeDefined();
  });

  it("registerAll fetches manifest and registers tools", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();

    expect(global.fetch).toHaveBeenCalledWith("/.well-known/webmcp.json");
    expect(navigator.modelContext!.registerTool).toHaveBeenCalledTimes(2);
  });

  it("getManifest returns manifest after registerAll", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();
    const manifest = webmcp.getManifest();
    expect(manifest.canister.name).toBe("Test Canister");
    expect(manifest.tools).toHaveLength(2);
  });

  it("getAgent returns agent after registerAll", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();
    expect(webmcp.getAgent()).toBeDefined();
  });

  it("getManifest throws before initialization", () => {
    const webmcp = new ICWebMCP();
    expect(() => webmcp.getManifest()).toThrow("not initialized");
  });

  it("getAgent throws before initialization", () => {
    const webmcp = new ICWebMCP();
    expect(() => webmcp.getAgent()).toThrow("not initialized");
  });

  it("unregisterAll unregisters all registered tools", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();
    await webmcp.unregisterAll();

    expect(navigator.modelContext!.unregisterTool).toHaveBeenCalledTimes(2);
    expect(navigator.modelContext!.unregisterTool).toHaveBeenCalledWith("greet");
    expect(navigator.modelContext!.unregisterTool).toHaveBeenCalledWith("transfer");
  });

  it("registerTool registers a single named tool", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();

    vi.mocked(navigator.modelContext!.registerTool).mockClear();
    await webmcp.registerTool("greet");

    expect(navigator.modelContext!.registerTool).toHaveBeenCalledOnce();
    const call = vi.mocked(navigator.modelContext!.registerTool).mock
      .calls[0][0] as import("../types.js").ModelContextTool;
    expect(call.name).toBe("greet");
  });

  it("registerTool throws for unknown tool name", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();
    await expect(webmcp.registerTool("nonexistent")).rejects.toThrow(
      "not found in manifest",
    );
  });

  it("setIdentity calls agent.replaceIdentity", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();
    const agent = webmcp.getAgent();

    const mockIdentity = {
      getPrincipal: vi.fn(),
    } as unknown as import("@icp-sdk/core/agent").Identity;
    webmcp.setIdentity(mockIdentity);

    expect(agent.replaceIdentity).toHaveBeenCalledWith(mockIdentity);
  });

  it("uses canisterId from config over manifest", async () => {
    const webmcp = new ICWebMCP({ canisterId: "aaaaa-aa" });
    await webmcp.registerAll();
    expect(webmcp.getManifest()).toBeDefined();
  });

  it("throws when no canisterId in config or manifest", async () => {
    mockFetchManifest({
      ...MANIFEST,
      canister: { name: "No ID", description: "test" },
    });
    const webmcp = new ICWebMCP();
    await expect(webmcp.registerAll()).rejects.toThrow("No canister ID");
  });

  it("does not re-fetch manifest on second registerAll", async () => {
    const webmcp = new ICWebMCP();
    await webmcp.registerAll();
    await webmcp.registerAll();
    // fetch only called once — subsequent call reuses existing manifest
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
});
