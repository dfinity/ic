import type { HttpAgent } from "@icp-sdk/core/agent";
import type { IDL } from "@icp-sdk/core/candid";
import { Principal } from "@icp-sdk/core/principal";
import { executeToolCall } from "./agent-bridge.js";
import type { WebMCPToolDefinition } from "./types.js";

/**
 * Register a canister tool with `navigator.modelContext`.
 *
 * This creates the bridge between the browser's WebMCP API and an IC canister
 * method: when an AI agent calls the tool, the execute callback translates
 * the JSON params into a canister call via @icp-sdk/core/agent.
 */
export async function registerTool(
  tool: WebMCPToolDefinition,
  agent: HttpAgent,
  canisterId: Principal,
  options?: {
    idlFactory?: IDL.InterfaceFactory;
    onAuthRequired?: () => Promise<void>;
  },
): Promise<void> {
  const modelContext = navigator.modelContext;
  if (!modelContext) {
    throw new Error(
      "navigator.modelContext is not available. WebMCP requires Chrome 146+ with the WebMCP flag enabled.",
    );
  }

  await modelContext.registerTool({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
    execute: async (params: Record<string, unknown>) => {
      // Check if auth is required
      if (tool.requires_auth) {
        const identity = await agent.config?.identity;
        const isAnonymous = !identity || identity.getPrincipal().isAnonymous();
        if (isAnonymous) {
          if (options?.onAuthRequired) {
            await options.onAuthRequired();
          } else {
            throw new Error(
              `Tool "${tool.name}" requires authentication. Please connect Internet Identity.`,
            );
          }
        }
      }

      const result = await executeToolCall(
        agent,
        canisterId,
        tool,
        params,
        options?.idlFactory,
      );

      return result.value;
    },
  });
}

/**
 * Unregister a tool from `navigator.modelContext`.
 */
export async function unregisterTool(name: string): Promise<void> {
  const modelContext = navigator.modelContext;
  if (!modelContext) return;
  await modelContext.unregisterTool(name);
}

/**
 * Register all tools from a manifest.
 */
export async function registerAllTools(
  tools: WebMCPToolDefinition[],
  agent: HttpAgent,
  canisterId: Principal,
  options?: {
    idlFactory?: IDL.InterfaceFactory;
    onAuthRequired?: () => Promise<void>;
  },
): Promise<void> {
  for (const tool of tools) {
    await registerTool(tool, agent, canisterId, options);
  }
}

/**
 * Unregister all tools from a manifest.
 */
export async function unregisterAllTools(
  tools: WebMCPToolDefinition[],
): Promise<void> {
  for (const tool of tools) {
    await unregisterTool(tool.name);
  }
}
