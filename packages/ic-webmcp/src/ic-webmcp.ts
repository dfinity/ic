import { HttpAgent, type Identity, type SignIdentity } from "@icp-sdk/core/agent";
import type { IDL } from "@icp-sdk/core/candid";
import { Principal } from "@icp-sdk/core/principal";
import {
  createScopedDelegation,
  getDelegationTargets,
} from "./auth.js";
import { fetchManifest } from "./manifest.js";
import {
  registerAllTools,
  unregisterAllTools,
} from "./tool-registry.js";
import type {
  ICWebMCPConfig,
  WebMCPManifest,
  WebMCPToolDefinition,
} from "./types.js";

/**
 * Main entry point for integrating Internet Computer canisters with WebMCP.
 *
 * Usage:
 * ```ts
 * const webmcp = new ICWebMCP({
 *   manifestUrl: '/.well-known/webmcp.json',
 * });
 * await webmcp.registerAll();
 * ```
 */
export class ICWebMCP {
  private config: ICWebMCPConfig;
  private agent: HttpAgent | null = null;
  private manifest: WebMCPManifest | null = null;
  private canisterId: Principal | null = null;
  private registeredTools: WebMCPToolDefinition[] = [];
  private idlFactory?: IDL.InterfaceFactory;

  constructor(config: ICWebMCPConfig = {}) {
    this.config = {
      manifestUrl: "/.well-known/webmcp.json",
      host: "https://icp-api.io",
      ...config,
    };
  }

  /**
   * Fetch the manifest and register all tools with navigator.modelContext.
   */
  async registerAll(): Promise<void> {
    await this.ensureInitialized();

    await registerAllTools(
      this.manifest!.tools,
      this.agent!,
      this.canisterId!,
      {
        idlFactory: this.idlFactory,
        onAuthRequired: this.config.onAuthRequired
          ? async () => {
              const identity = await this.config.onAuthRequired!();
              this.setIdentity(identity);
            }
          : undefined,
      },
    );

    this.registeredTools = [...this.manifest!.tools];
  }

  /**
   * Register a single tool by name.
   */
  async registerTool(toolName: string): Promise<void> {
    await this.ensureInitialized();

    const tool = this.manifest!.tools.find((t) => t.name === toolName);
    if (!tool) {
      throw new Error(
        `Tool "${toolName}" not found in manifest. Available: ${this.manifest!.tools.map((t) => t.name).join(", ")}`,
      );
    }

    const { registerTool: regTool } = await import("./tool-registry.js");
    await regTool(tool, this.agent!, this.canisterId!, {
      idlFactory: this.idlFactory,
      onAuthRequired: this.config.onAuthRequired
        ? async () => {
            const identity = await this.config.onAuthRequired!();
            this.setIdentity(identity);
          }
        : undefined,
    });

    this.registeredTools.push(tool);
  }

  /**
   * Unregister all previously registered tools.
   */
  async unregisterAll(): Promise<void> {
    await unregisterAllTools(this.registeredTools);
    this.registeredTools = [];
  }

  /**
   * Get the underlying HttpAgent.
   */
  getAgent(): HttpAgent {
    if (!this.agent) {
      throw new Error("ICWebMCP not initialized. Call registerAll() first.");
    }
    return this.agent;
  }

  /**
   * Get the loaded manifest.
   */
  getManifest(): WebMCPManifest {
    if (!this.manifest) {
      throw new Error("ICWebMCP not initialized. Call registerAll() first.");
    }
    return this.manifest;
  }

  /**
   * Set or update the identity used for canister calls.
   */
  setIdentity(identity: Identity): void {
    if (this.agent) {
      this.agent.replaceIdentity(identity);
    }
    this.config.identity = identity;
  }

  /**
   * Provide an IDL factory for typed Actor-based calls.
   * If not set, calls use raw agent encoding.
   */
  setIdlFactory(factory: IDL.InterfaceFactory): void {
    this.idlFactory = factory;
  }

  /**
   * Create a scoped delegation identity for agent authentication.
   *
   * Generates a short-lived, canister-scoped delegation from the current
   * identity, suitable for granting an AI agent limited access.
   */
  async createAgentDelegation(options?: {
    maxTtlSeconds?: number;
  }): Promise<Identity> {
    if (!this.config.identity) {
      throw new Error(
        "No identity set. Connect Internet Identity before creating a delegation.",
      );
    }
    if (!this.canisterId) {
      throw new Error("ICWebMCP not initialized.");
    }

    const targets = getDelegationTargets(
      this.canisterId.toText(),
      this.manifest?.authentication,
    );

    return createScopedDelegation({
      baseIdentity: this.config.identity as SignIdentity,
      targets,
      maxTtlSeconds: options?.maxTtlSeconds ?? 3600,
    });
  }

  private async ensureInitialized(): Promise<void> {
    if (this.manifest && this.agent && this.canisterId) {
      return;
    }

    // Fetch manifest
    this.manifest = await fetchManifest(this.config.manifestUrl);

    // Resolve canister ID
    const canisterIdText =
      this.config.canisterId ?? this.manifest.canister.id;
    if (!canisterIdText) {
      throw new Error(
        "No canister ID provided in config or manifest. Set canisterId in ICWebMCPConfig or in webmcp.json.",
      );
    }
    this.canisterId = Principal.fromText(canisterIdText);

    // Create agent
    this.agent = await HttpAgent.create({
      host: this.config.host,
      identity: this.config.identity,
    });

    // In development, fetch the root key
    if (
      this.config.host &&
      (this.config.host.includes("localhost") ||
        this.config.host.includes("127.0.0.1"))
    ) {
      await this.agent.fetchRootKey();
    }
  }
}
