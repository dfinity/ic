import { Actor, HttpAgent, type QueryResponseStatus } from "@icp-sdk/core/agent";
import type { QueryResponseReplied } from "@icp-sdk/core/agent";
import { IDL } from "@icp-sdk/core/candid";
import { Principal } from "@icp-sdk/core/principal";
import { candidToJson } from "./candid-json.js";
import { wrapCertifiedResponse } from "./certified-response.js";
import type { WebMCPToolDefinition, ToolExecuteResult } from "./types.js";

/**
 * Execute a canister call for a WebMCP tool invocation.
 *
 * Maps the JSON parameters from a tool call into a Candid-encoded
 * canister call via @icp-sdk/core/agent, then decodes the response back to JSON.
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

  // For update calls and non-certified queries, return the value directly.
  if (!tool.certified || tool.method_type !== "query") {
    return { value: result, certified: false };
  }

  // For certified queries via Actor, we need the raw response to access
  // node signatures. Actor.createActor wraps calls and loses the raw response,
  // so fall through to the raw query path for certified tools.
  return executeCertifiedQuery(agent, canisterId, tool);
}

async function executeRawCall(
  agent: HttpAgent,
  canisterId: Principal,
  tool: WebMCPToolDefinition,
  params: Record<string, unknown>,
): Promise<ToolExecuteResult> {
  // Without an IDL factory we can only safely call zero-argument methods.
  // For any method that accepts parameters the caller must supply an idlFactory
  // so we can encode the Candid payload correctly.
  const hasParams = Object.keys(params).length > 0;
  if (hasParams) {
    throw new Error(
      `Tool "${tool.canister_method}" requires an idlFactory to encode parameters. ` +
        `Pass an IDL factory via ICWebMCP.setIdlFactory() or the idlFactory option.`,
    );
  }

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

    const replied = response as { reply?: { arg: Uint8Array } };
    const value = replied.reply?.arg
      ? candidToJson(replied.reply.arg, [])
      : null;

    // Propagate signature metadata for certified tools.
    // The agent verifies signatures automatically (verifyQuerySignatures: true
    // by default) and throws before we reach here if verification fails.
    if (tool.certified) {
      const signatures = (response as Partial<QueryResponseReplied>).signatures;
      return wrapCertifiedResponse(value, signatures);
    }

    return { value };
  } else {
    const { response } = await agent.call(canisterId, {
      methodName: tool.canister_method,
      arg,
    });

    return { value: response };
  }
}

/**
 * Execute a certified query directly via the raw agent to access node signatures.
 *
 * Actor calls wrap the response and lose the signatures array, so for
 * `certified: true` tools we drop back to raw agent.query() which exposes
 * the full QueryResponseReplied including signatures.
 *
 * @icp-sdk/core/agent verifies signatures before returning (verifyQuerySignatures
 * defaults to true), so if we reach here the response is already verified.
 */
async function executeCertifiedQuery(
  agent: HttpAgent,
  canisterId: Principal,
  tool: WebMCPToolDefinition,
): Promise<ToolExecuteResult> {
  const arg = IDL.encode([], []);
  const response = await agent.query(canisterId, {
    methodName: tool.canister_method,
    arg,
  });

  if (response.status === ("rejected" as unknown as QueryResponseStatus)) {
    const rejected = response as { reject_message?: string };
    throw new Error(
      `Certified query "${tool.canister_method}" rejected: ${rejected.reject_message ?? "unknown error"}`,
    );
  }

  const replied = response as Partial<QueryResponseReplied>;
  const value = replied.reply?.arg ? candidToJson(replied.reply.arg, []) : null;
  return wrapCertifiedResponse(value, replied.signatures);
}

/**
 * Convert JSON params into positional args for an Actor method call.
 *
 * - Zero-argument methods: params will be `{}` from the empty inputSchema;
 *   return `[]` so the Actor call receives no arguments.
 * - Positional-arg methods: params have `arg0`, `arg1`, … keys; extract in order.
 * - Single record-arg methods: pass the whole params object directly.
 */
function buildActorArgs(params: Record<string, unknown>): unknown[] {
  // Zero-argument method — don't pass anything
  if (Object.keys(params).length === 0) {
    return [];
  }

  // Positional arg naming (multi-arg methods)
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
