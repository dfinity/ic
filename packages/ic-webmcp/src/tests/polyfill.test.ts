import { describe, it, expect, beforeEach } from "vitest";
import {
  installPolyfill,
  clearRegistry,
  getRegisteredTools,
  getOpenAITools,
  getAnthropicTools,
  getLangChainTools,
  dispatchToolCall,
} from "../polyfill.js";
import type { ModelContextTool } from "../types.js";

const TOOL: ModelContextTool = {
  name: "greet",
  description: "Say hello",
  inputSchema: { type: "object", properties: { name: { type: "string" } } },
  execute: async (params) => `Hello, ${params.name}!`,
};

const AUTH_TOOL: ModelContextTool = {
  name: "transfer",
  description: "Transfer tokens",
  inputSchema: { type: "object", properties: { amount: { type: "string" } } },
  execute: async (params) => ({ transferred: params.amount }),
};

beforeEach(() => {
  // Reinstall polyfill and clear the registry between tests
  installPolyfill(true);
  clearRegistry();
});

describe("installPolyfill", () => {
  it("installs navigator.modelContext when absent", () => {
    installPolyfill(true);
    expect(navigator.modelContext).toBeDefined();
  });

  it("is idempotent without force flag once installed", () => {
    installPolyfill(false);
    const ctx1 = navigator.modelContext;
    installPolyfill(false);
    expect(navigator.modelContext).toBe(ctx1);
  });
});

describe("getRegisteredTools", () => {
  it("returns empty array before any tools are registered", () => {
    expect(getRegisteredTools()).toHaveLength(0);
  });

  it("returns tools after registration", async () => {
    await navigator.modelContext!.registerTool(TOOL);
    expect(getRegisteredTools()).toHaveLength(1);
    expect(getRegisteredTools()[0].name).toBe("greet");
  });

  it("reflects unregistration", async () => {
    await navigator.modelContext!.registerTool(TOOL);
    await navigator.modelContext!.unregisterTool("greet");
    expect(getRegisteredTools()).toHaveLength(0);
  });
});

describe("getOpenAITools", () => {
  it("returns correct OpenAI function format", async () => {
    await navigator.modelContext!.registerTool(TOOL);
    const tools = getOpenAITools();
    expect(tools).toHaveLength(1);
    expect(tools[0].type).toBe("function");
    expect(tools[0].function.name).toBe("greet");
    expect(tools[0].function.description).toBe("Say hello");
    expect(tools[0].function.parameters).toEqual(TOOL.inputSchema);
  });

  it("returns multiple tools", async () => {
    await navigator.modelContext!.registerTool(TOOL);
    await navigator.modelContext!.registerTool(AUTH_TOOL);
    expect(getOpenAITools()).toHaveLength(2);
  });
});

describe("getAnthropicTools", () => {
  it("returns correct Anthropic tool format", async () => {
    await navigator.modelContext!.registerTool(TOOL);
    const tools = getAnthropicTools();
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe("greet");
    expect(tools[0].description).toBe("Say hello");
    expect(tools[0].input_schema).toEqual(TOOL.inputSchema);
  });
});

describe("getLangChainTools", () => {
  it("returns tools with func that JSON-stringifies results", async () => {
    await navigator.modelContext!.registerTool(AUTH_TOOL);
    const tools = getLangChainTools();
    expect(tools).toHaveLength(1);
    const result = await tools[0].func({ amount: "100" });
    expect(JSON.parse(result)).toEqual({ transferred: "100" });
  });
});

describe("dispatchToolCall", () => {
  it("dispatches to the correct registered tool", async () => {
    await navigator.modelContext!.registerTool(TOOL);
    const result = await dispatchToolCall("greet", { name: "World" });
    expect(result).toBe("Hello, World!");
  });

  it("throws for unknown tool names", async () => {
    await expect(dispatchToolCall("unknown", {})).rejects.toThrow(
      "No tool named",
    );
  });

  it("lists available tools in error message", async () => {
    await navigator.modelContext!.registerTool(TOOL);
    await expect(dispatchToolCall("no_such", {})).rejects.toThrow("greet");
  });
});
