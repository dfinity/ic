import type { Identity } from "@icp-sdk/core/agent";

// ── WebMCP Manifest (mirrors webmcp.json from codegen) ──────────────

export interface WebMCPManifest {
  schema_version: string;
  canister: CanisterInfo;
  tools: WebMCPToolDefinition[];
  authentication?: AuthenticationInfo;
}

export interface CanisterInfo {
  id?: string;
  name: string;
  description: string;
}

export interface WebMCPToolDefinition {
  name: string;
  description: string;
  canister_method: string;
  method_type: "query" | "update";
  certified?: boolean;
  requires_auth?: boolean;
  inputSchema: JsonSchema;
  outputSchema?: JsonSchema;
}

export interface AuthenticationInfo {
  type: string;
  delegation_targets?: string[];
  recommended_scope?: Record<
    string,
    {
      max_ttl_seconds?: number;
      description?: string;
    }
  >;
}

// ── JSON Schema subset ──────────────────────────────────────────────

export type JsonSchema = Record<string, unknown>;

// ── ICWebMCP Configuration ──────────────────────────────────────────

export interface ICWebMCPConfig {
  /** URL to fetch the manifest from. Default: '/.well-known/webmcp.json' */
  manifestUrl?: string;

  /** Override canister ID (otherwise read from manifest). */
  canisterId?: string;

  /** IC replica host. Default: 'https://icp-api.io' */
  host?: string;

  /** Pre-existing identity to use for calls. */
  identity?: Identity;

  /** Callback invoked when a tool requires authentication. */
  onAuthRequired?: () => Promise<Identity>;
}

// ── Tool Execution ──────────────────────────────────────────────────

export interface ToolExecuteResult {
  value: unknown;
  /** True when node signatures were present and verified by @icp-sdk/core/agent. */
  certified?: boolean;
  /** Signing node metadata from the query response, when certified is true. */
  signatures?: Array<{ nodeId: string; timestampNanos: bigint }>;
}

// ── navigator.modelContext types (Chrome 146+) ──────────────────────
// These represent the browser API surface. Declared here so the
// library compiles without Chrome-specific type defs.

export interface ModelContextTool {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  execute: (params: Record<string, unknown>) => Promise<unknown>;
}

export interface ModelContextAPI {
  registerTool(tool: ModelContextTool): Promise<void>;
  unregisterTool(name: string): Promise<void>;
}

declare global {
  interface Navigator {
    modelContext?: ModelContextAPI;
  }
}
