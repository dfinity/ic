/**
 * WebMCP polyfill for non-Chrome browsers and server-side agent frameworks.
 *
 * Chrome 146+ ships `navigator.modelContext` natively. This polyfill:
 * 1. Installs a compatible `navigator.modelContext` shim in browsers that
 *    don't have it, so WebMCP tool registration works everywhere.
 * 2. Exposes registered tools in formats understood by popular AI agent
 *    frameworks: OpenAI function calling, LangChain, Anthropic tool use.
 *
 * ## Browser usage
 * ```ts
 * import { installPolyfill } from '@dfinity/webmcp';
 * installPolyfill();          // call before ICWebMCP.registerAll()
 * ```
 *
 * ## Server / agent framework usage
 * ```ts
 * import { installPolyfill, getOpenAITools } from '@dfinity/webmcp';
 * installPolyfill();
 * const webmcp = new ICWebMCP();
 * await webmcp.registerAll();
 * const tools = getOpenAITools();   // pass to OpenAI SDK
 * ```
 */

import type { JsonSchema, ModelContextAPI, ModelContextTool } from "./types.js";

// ── In-memory tool registry ───────────────────────────────────────────

const _registry = new Map<string, ModelContextTool>();

/** Polyfill implementation of navigator.modelContext. */
const polyfillContext: ModelContextAPI = {
  async registerTool(tool: ModelContextTool): Promise<void> {
    _registry.set(tool.name, tool);
  },
  async unregisterTool(name: string): Promise<void> {
    _registry.delete(name);
  },
};

// ── Installation ──────────────────────────────────────────────────────

/**
 * Clear all registered tools from the polyfill registry.
 * Useful in tests and when re-initialising the page.
 */
export function clearRegistry(): void {
  _registry.clear();
}

/**
 * Install the WebMCP polyfill.
 *
 * If `navigator.modelContext` is already present (Chrome 146+) this is a
 * no-op. Otherwise, installs the in-memory shim so `ICWebMCP.registerAll()`
 * works in any environment (other browsers, Node.js, test runners).
 *
 * @param force - Install even if navigator.modelContext already exists.
 *                Useful in tests to capture tool registrations.
 */
export function installPolyfill(force = false): void {
  if (typeof navigator === "undefined") {
    // Node.js / non-browser: create a minimal navigator global
    (globalThis as Record<string, unknown>).navigator = {};
  }
  if (!force && navigator.modelContext !== undefined) {
    return; // Native implementation present
  }
  Object.defineProperty(navigator, "modelContext", {
    value: polyfillContext,
    writable: true,
    configurable: true,
  });
}

/**
 * Return all currently registered tools from the polyfill registry.
 * Returns an empty array if the polyfill is not installed.
 */
export function getRegisteredTools(): ModelContextTool[] {
  return Array.from(_registry.values());
}

// ── Framework adapters ────────────────────────────────────────────────

/**
 * OpenAI function calling format.
 * Pass the result directly to the `tools` parameter of `openai.chat.completions.create()`.
 *
 * @see https://platform.openai.com/docs/guides/function-calling
 */
export interface OpenAITool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: JsonSchema;
  };
}

/**
 * Export registered tools in OpenAI function calling format.
 *
 * ```ts
 * const completion = await openai.chat.completions.create({
 *   model: "gpt-4o",
 *   tools: getOpenAITools(),
 *   messages,
 * });
 * ```
 */
export function getOpenAITools(): OpenAITool[] {
  return getRegisteredTools().map((tool) => ({
    type: "function" as const,
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema,
    },
  }));
}

/**
 * Anthropic tool use format.
 * Pass the result directly to the `tools` parameter of the Messages API.
 *
 * @see https://docs.anthropic.com/en/docs/build-with-claude/tool-use
 */
export interface AnthropicTool {
  name: string;
  description: string;
  input_schema: JsonSchema;
}

/**
 * Export registered tools in Anthropic tool use format.
 *
 * ```ts
 * const message = await anthropic.messages.create({
 *   model: "claude-opus-4-5",
 *   tools: getAnthropicTools(),
 *   messages,
 * });
 * ```
 */
export function getAnthropicTools(): AnthropicTool[] {
  return getRegisteredTools().map((tool) => ({
    name: tool.name,
    description: tool.description,
    input_schema: tool.inputSchema,
  }));
}

/**
 * Generic tool definition compatible with LangChain's `StructuredTool` interface.
 *
 * ```ts
 * import { DynamicStructuredTool } from "@langchain/core/tools";
 *
 * const lcTools = getLangChainTools().map(
 *   (t) => new DynamicStructuredTool({
 *     name: t.name,
 *     description: t.description,
 *     schema: t.schema,
 *     func: t.func,
 *   })
 * );
 * ```
 */
export interface LangChainToolDef {
  name: string;
  description: string;
  schema: JsonSchema;
  func: (input: Record<string, unknown>) => Promise<string>;
}

/**
 * Export registered tools in a LangChain-compatible format.
 * Tool results are JSON-stringified for LangChain's string-based tool output.
 */
export function getLangChainTools(): LangChainToolDef[] {
  return getRegisteredTools().map((tool) => ({
    name: tool.name,
    description: tool.description,
    schema: tool.inputSchema,
    func: async (input: Record<string, unknown>): Promise<string> => {
      const result = await tool.execute(input);
      return JSON.stringify(result);
    },
  }));
}

/**
 * Dispatch a tool call from a framework's response back to the registered tool.
 *
 * Works with OpenAI, Anthropic, and any framework that identifies tools by name.
 *
 * ```ts
 * // After receiving a tool_use block from Anthropic:
 * const result = await dispatchToolCall(block.name, block.input);
 * ```
 */
export async function dispatchToolCall(
  toolName: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const tool = _registry.get(toolName);
  if (!tool) {
    throw new Error(
      `No tool named "${toolName}" is registered. ` +
        `Available tools: ${Array.from(_registry.keys()).join(", ") || "(none)"}`,
    );
  }
  return tool.execute(params);
}
