import { Actor, HttpAgent, type QueryResponseStatus } from "@dfinity/agent";
import { IDL } from "@dfinity/candid";
import { Principal } from "@dfinity/principal";
import { candidToJson } from "./candid-json.js";
import type { WebMCPToolDefinition, ToolExecuteResult } from "./types.js";

/**
 * Execute a canister call for a WebMCP tool invocation.
 *
 * Maps the JSON parameters from a tool call into a Candid-encoded
 * canister call via @dfinity/agent, then decodes the response back to JSON.
 */
export async function executeToolCall(
  agent: HttpAgent,
  canisterId: Principal,
  tool: WebMCPToolDefinition,
  params: Record<string, unknown>,
  idlFactory?: IDL.InterfaceFactory,
): Promise<ToolExecuteResult> {
  // If we have an IDL factory (from .did), use Actor for typed calls
  if (idlFactory) {
    return executeViaActor(agent, canisterId, tool, params, idlFactory);
  }

  // Fallback: raw agent call with empty arg encoding
  return executeRawCall(agent, canisterId, tool, params);
}

async function executeViaActor(
  agent: HttpAgent,
  canisterId: Principal,
  tool: WebMCPToolDefinition,
  params: Record<string, unknown>,
  idlFactory: IDL.InterfaceFactory,
): Promise<ToolExecuteResult> {
  const actor = Actor.createActor(idlFactory, {
    agent,
    canisterId,
  });

  const method = actor[tool.canister_method] as (
    ...args: unknown[]
  ) => Promise<unknown>;
  if (typeof method !== "function") {
    throw new Error(
      `Method "${tool.canister_method}" not found on actor for canister ${canisterId.toText()}`,
    );
  }

  // For Actor calls, we pass params as-is — the Actor handles encoding.
  // Single-record-arg methods receive the params object directly.
  // Multi-arg methods receive positional args.
  const args = buildActorArgs(params);
  const result = await method(...args);

  return { value: result };
}

async function executeRawCall(
  agent: HttpAgent,
  canisterId: Principal,
  tool: WebMCPToolDefinition,
  params: Record<string, unknown>,
): Promise<ToolExecuteResult> {
  // Without an IDL factory, we encode with an empty type list
  // and pass the params as-is. This is a best-effort fallback.
  const arg = IDL.encode([], []);

  if (tool.method_type === "query") {
    const response = await agent.query(canisterId, {
      methodName: tool.canister_method,
      arg,
    });

    if (response.status === ("rejected" as unknown as QueryResponseStatus)) {
      const rejected = response as { reject_code?: number; reject_message?: string };
      throw new Error(
        `Query "${tool.canister_method}" rejected: ${rejected.reject_message ?? "unknown error"}`,
      );
    }

    const replied = response as { reply?: { arg: ArrayBuffer } };
    return {
      value: replied.reply?.arg
        ? candidToJson(replied.reply.arg, [])
        : null,
    };
  } else {
    const { response } = await agent.call(canisterId, {
      methodName: tool.canister_method,
      arg,
    });

    return { value: response };
  }
}

/**
 * Convert JSON params into positional args for an Actor method call.
 *
 * If params have positional keys (arg0, arg1, ...), extract them in order.
 * Otherwise, pass the entire params object as a single argument (record).
 */
function buildActorArgs(params: Record<string, unknown>): unknown[] {
  // Check if params use positional arg naming
  if ("arg0" in params) {
    const args: unknown[] = [];
    let i = 0;
    while (`arg${i}` in params) {
      args.push(params[`arg${i}`]);
      i++;
    }
    return args;
  }

  // Single record argument — pass the whole params object
  return [params];
}
