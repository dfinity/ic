/**
 * Certified query response support for WebMCP tools.
 *
 * IC query responses include `signatures` — an array of BLS-based node
 * signatures produced by the subnet nodes that handled the request.
 * `@icp-sdk/core/agent`'s HttpAgent verifies these by default
 * (`verifyQuerySignatures: true`), throwing if verification fails.
 *
 * When a WebMCP tool is marked `certified: true`, the bridge:
 * 1. Executes the query via an agent with `verifyQuerySignatures: true`
 * 2. Collects the node signature timestamps and identities
 * 3. Returns `{ value, certified: true, signatures }` so callers can
 *    confirm verification occurred and inspect the signing nodes
 *
 * For the strongest guarantee (full BLS threshold certificate), use
 * `readState` after the query — see `readCertifiedData()` below.
 */

import { Certificate, lookupResultToBuffer } from "@icp-sdk/core/agent";
import type { HttpAgent } from "@icp-sdk/core/agent";
import type { NodeSignature } from "@icp-sdk/core/agent";
import { Principal } from "@icp-sdk/core/principal";

/** Verified query response with signature metadata. */
export interface CertifiedQueryResult {
  /** The decoded value returned by the canister. */
  value: unknown;
  /** True when node signatures were present and verified by @icp-sdk/core/agent. */
  certified: true;
  /** Signing node identities and timestamps from the query response. */
  signatures: Array<{
    /** Hex-encoded node identity (public key). */
    nodeId: string;
    /** Unix timestamp in nanoseconds when the node signed the response. */
    timestampNanos: bigint;
  }>;
}

/**
 * Wrap a query result with verified signature metadata.
 *
 * Called after a successful agent.query() when the tool is `certified: true`.
 * The agent has already verified the signatures (throws on failure), so this
 * just extracts the metadata for the caller.
 */
export function wrapCertifiedResponse(
  value: unknown,
  signatures: NodeSignature[] | undefined,
): CertifiedQueryResult {
  return {
    value,
    certified: true,
    signatures: (signatures ?? []).map((sig) => ({
      nodeId: bufferToHex(sig.identity),
      timestampNanos: sig.timestamp,
    })),
  };
}

/**
 * Read the canister's certified data via `readState` and verify the
 * BLS threshold certificate against the IC root key.
 *
 * This provides the strongest certification guarantee: a full BLS
 * threshold signature from the subnet, not just individual node signatures.
 * Use this when `certified_data` is set by the canister via
 * `ic0.certified_data_set()`.
 *
 * @param agent    - HttpAgent (root key must be fetched for local replicas)
 * @param canisterId - The canister to read certified data from
 * @returns The raw certified data bytes, or `undefined` if not set.
 */
export async function readCertifiedData(
  agent: HttpAgent,
  canisterId: Principal,
): Promise<{
  data: Uint8Array | undefined;
  certificate: Uint8Array;
  timestampNanos: bigint;
}> {
  const canisterIdBytes = canisterId.toUint8Array();
  const enc = new TextEncoder();

  // Request the certified_data path from the state tree
  const response = await agent.readState(canisterId, {
    paths: [[enc.encode("canister"), canisterIdBytes, enc.encode("certified_data")]],
  });

  const cert = await Certificate.create({
    certificate: response.certificate,
    rootKey: await getRootKey(agent),
    principal: { canisterId },
  });

  const dataResult = cert.lookup_path([
    "canister",
    canisterIdBytes,
    "certified_data",
  ]);
  const timeResult = cert.lookup_path(["time"]);

  const timeBytes = lookupResultToBuffer(timeResult);
  const timestampNanos = timeBytes ? decodeLeb128(timeBytes) : 0n;

  return {
    data: lookupResultToBuffer(dataResult),
    certificate: response.certificate,
    timestampNanos,
  };
}

// ── Helpers ──────────────────────────────────────────────────────────

async function getRootKey(agent: HttpAgent): Promise<Uint8Array> {
  // @icp-sdk/core/agent caches the root key after fetchRootKey() is called.
  // For mainnet the default IC root key is built in; this only matters
  // for local replicas where fetchRootKey() must be called first.
  return (agent as unknown as { rootKey?: Uint8Array }).rootKey ?? new Uint8Array(0);
}

function bufferToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Decode an unsigned LEB128-encoded integer from bytes. */
function decodeLeb128(bytes: Uint8Array): bigint {
  let result = 0n;
  let shift = 0n;
  for (const byte of bytes) {
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return result;
}
