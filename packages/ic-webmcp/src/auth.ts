import type { SignIdentity } from "@dfinity/agent";
import {
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@dfinity/identity";
import { Principal } from "@dfinity/principal";
import type { AuthenticationInfo } from "./types.js";

export interface CreateDelegationOptions {
  /** The user's base identity (from Internet Identity login). Must be a SignIdentity. */
  baseIdentity: SignIdentity;

  /** Canister IDs this delegation is scoped to. */
  targets?: Principal[];

  /** Maximum time-to-live in seconds. Default: 3600 (1 hour). */
  maxTtlSeconds?: number;
}

/**
 * Create a scoped delegation identity for AI agent use.
 *
 * This generates a short-lived, canister-scoped delegation from the user's
 * Internet Identity, suitable for granting an AI agent limited access to
 * specific canister methods.
 *
 * The delegation chain restricts:
 * - Which canisters can be called (via `targets`)
 * - How long the delegation is valid (via `maxTtlSeconds`)
 *
 * @returns A DelegationIdentity that the agent can use for canister calls.
 */
export async function createScopedDelegation(
  options: CreateDelegationOptions,
): Promise<DelegationIdentity> {
  const { baseIdentity, targets = [], maxTtlSeconds = 3600 } = options;

  // Generate an ephemeral key pair for the delegated identity
  const sessionKey = Ed25519KeyIdentity.generate();

  // Create delegation chain from the base identity to the session key
  const chain = await DelegationChain.create(
    baseIdentity,
    sessionKey.getPublicKey(),
    new Date(Date.now() + maxTtlSeconds * 1000),
    {
      targets: targets.length > 0 ? targets : undefined,
    },
  );

  return DelegationIdentity.fromDelegation(sessionKey, chain);
}

/**
 * Build delegation targets from manifest authentication info and canister ID.
 */
export function getDelegationTargets(
  canisterId: string,
  auth?: AuthenticationInfo,
): Principal[] {
  const targets = new Set<string>();
  targets.add(canisterId);

  if (auth?.delegation_targets) {
    for (const target of auth.delegation_targets) {
      targets.add(target);
    }
  }

  return Array.from(targets).map((id) => Principal.fromText(id));
}
