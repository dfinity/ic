import { describe, it, expect, vi, beforeEach } from "vitest";
import { Principal } from "@icp-sdk/core/principal";
import {
  registerTool,
  unregisterTool,
  registerAllTools,
  unregisterAllTools,
} from "../tool-registry.js";
import type { WebMCPToolDefinition, ModelContextTool } from "../types.js";

// ── Fixtures ─────────────────────────────────────────────────────────

const QUERY_TOOL: WebMCPToolDefinition = {
  name: "greet",
  description: "Say hello",
  canister_method: "greet",
  method_type: "query",
  inputSchema: { type: "object", properties: { name: { type: "string" } } },
};

const AUTH_TOOL: WebMCPToolDefinition = {
  name: "transfer",
  description: "Transfer tokens",
  canister_method: "transfer",
  method_type: "update",
  requires_auth: true,
  inputSchema: { type: "object", properties: { amount: { type: "string" } } },
};

const CANISTER_ID = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai");

function makeAgent(isAnonymous = true) {
  const mockPrincipal = {
    isAnonymous: () => isAnonymous,
    toText: () => (isAnonymous ? "2vxsx-fae" : "aaaaa-aa"),
  };
  return {
    config: {
      identity: Promise.resolve({
        getPrincipal: () => mockPrincipal,
      }),
    },
    query: vi.fn().mockResolvedValue({
      status: "replied",
      reply: { arg: new ArrayBuffer(0) },
    }),
    call: vi.fn().mockResolvedValue({ response: {} }),
  } as unknown as import("@icp-sdk/core/agent").HttpAgent;
}

function makeModelContext() {
  const registered = new Map<string, unknown>();
  return {
    registerTool: vi.fn(async (tool: { name: string }) => {
      registered.set(tool.name, tool);
    }),
    unregisterTool: vi.fn(async (name: string) => {
      registered.delete(name);
    }),
    _registered: registered,
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

// ── Tests ─────────────────────────────────────────────────────────────

describe("registerTool", () => {
  it("throws if navigator.modelContext is unavailable", async () => {
    Object.defineProperty(global, "navigator", {
      value: {},
      writable: true,
      configurable: true,
    });

    await expect(
      registerTool(QUERY_TOOL, makeAgent(), CANISTER_ID),
    ).rejects.toThrow("navigator.modelContext is not available");
  });

  it("registers a tool with navigator.modelContext", async () => {
    const ctx = makeModelContext();
    Object.defineProperty(global, "navigator", {
      value: { modelContext: ctx },
      writable: true,
      configurable: true,
    });

    await registerTool(QUERY_TOOL, makeAgent(), CANISTER_ID);

    expect(ctx.registerTool).toHaveBeenCalledOnce();
    const call = ctx.registerTool.mock.calls[0][0] as ModelContextTool;
    expect(call.name).toBe("greet");
    expect(call.description).toBe("Say hello");
    expect(typeof call.execute).toBe("function");
  });

  it("calls onAuthRequired when auth tool is called anonymously", async () => {
    const ctx = makeModelContext();
    Object.defineProperty(global, "navigator", {
      value: { modelContext: ctx },
      writable: true,
      configurable: true,
    });

    const onAuthRequired = vi.fn().mockResolvedValue(undefined);
    await registerTool(AUTH_TOOL, makeAgent(true), CANISTER_ID, {
      onAuthRequired,
    });

    // Auth check fires first; the call then fails because no idlFactory was
    // provided — but the important assertion is that onAuthRequired ran.
    const registeredCall = ctx.registerTool.mock.calls[0][0] as ModelContextTool;
    await expect(registeredCall.execute({ amount: "100" })).rejects.toThrow(
      "idlFactory",
    );
    expect(onAuthRequired).toHaveBeenCalledOnce();
  });

  it("throws when auth tool called anonymously with no onAuthRequired", async () => {
    const ctx = makeModelContext();
    Object.defineProperty(global, "navigator", {
      value: { modelContext: ctx },
      writable: true,
      configurable: true,
    });

    await registerTool(AUTH_TOOL, makeAgent(true), CANISTER_ID);

    const registeredCall = ctx.registerTool.mock.calls[0][0] as ModelContextTool;
    await expect(registeredCall.execute({ amount: "100" })).rejects.toThrow(
      "requires authentication",
    );
  });
});

describe("unregisterTool", () => {
  it("calls modelContext.unregisterTool", async () => {
    const ctx = makeModelContext();
    Object.defineProperty(global, "navigator", {
      value: { modelContext: ctx },
      writable: true,
      configurable: true,
    });

    await unregisterTool("greet");
    expect(ctx.unregisterTool).toHaveBeenCalledWith("greet");
  });

  it("is a no-op if modelContext is unavailable", async () => {
    Object.defineProperty(global, "navigator", {
      value: {},
      writable: true,
      configurable: true,
    });
    await expect(unregisterTool("greet")).resolves.toBeUndefined();
  });
});

describe("registerAllTools / unregisterAllTools", () => {
  it("registers all tools in order", async () => {
    const ctx = makeModelContext();
    Object.defineProperty(global, "navigator", {
      value: { modelContext: ctx },
      writable: true,
      configurable: true,
    });

    const tools = [QUERY_TOOL, AUTH_TOOL];
    await registerAllTools(tools, makeAgent(), CANISTER_ID);

    expect(ctx.registerTool).toHaveBeenCalledTimes(2);
    expect(ctx.registerTool.mock.calls[0][0].name).toBe("greet");
    expect(ctx.registerTool.mock.calls[1][0].name).toBe("transfer");
  });

  it("unregisters all tools", async () => {
    const ctx = makeModelContext();
    Object.defineProperty(global, "navigator", {
      value: { modelContext: ctx },
      writable: true,
      configurable: true,
    });

    await unregisterAllTools([QUERY_TOOL, AUTH_TOOL]);
    expect(ctx.unregisterTool).toHaveBeenCalledTimes(2);
    expect(ctx.unregisterTool).toHaveBeenCalledWith("greet");
    expect(ctx.unregisterTool).toHaveBeenCalledWith("transfer");
  });
});
