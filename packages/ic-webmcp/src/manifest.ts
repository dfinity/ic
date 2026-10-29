import type { WebMCPManifest } from "./types.js";

const DEFAULT_MANIFEST_URL = "/.well-known/webmcp.json";

/**
 * Fetch and parse a WebMCP manifest from a URL.
 *
 * @param url - URL to fetch the manifest from. Defaults to `/.well-known/webmcp.json`.
 * @returns The parsed manifest.
 * @throws If the fetch fails or the response is not valid JSON.
 */
export async function fetchManifest(
  url: string = DEFAULT_MANIFEST_URL,
): Promise<WebMCPManifest> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch WebMCP manifest from ${url}: ${response.status} ${response.statusText}`,
    );
  }

  const manifest: WebMCPManifest = await response.json();
  validateManifest(manifest);
  return manifest;
}

function validateManifest(manifest: WebMCPManifest): void {
  if (!manifest.schema_version) {
    throw new Error("WebMCP manifest missing schema_version");
  }
  if (!manifest.canister) {
    throw new Error("WebMCP manifest missing canister info");
  }
  if (!Array.isArray(manifest.tools) || manifest.tools.length === 0) {
    throw new Error("WebMCP manifest has no tools defined");
  }
  for (const tool of manifest.tools) {
    if (!tool.name || !tool.canister_method || !tool.inputSchema) {
      throw new Error(
        `WebMCP tool "${tool.name ?? "unknown"}" is missing required fields`,
      );
    }
    if (tool.method_type !== "query" && tool.method_type !== "update") {
      throw new Error(
        `WebMCP tool "${tool.name}" has invalid method_type: ${tool.method_type}`,
      );
    }
  }
}
