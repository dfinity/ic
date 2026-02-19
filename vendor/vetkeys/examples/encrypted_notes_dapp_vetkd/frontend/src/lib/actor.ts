import {
  Actor,
  ActorConfig,
  ActorSubclass,
  HttpAgent,
  HttpAgentOptions,
} from "@dfinity/agent";
import {
  idlFactory,
  _SERVICE,
} from "../declarations/encrypted_notes/encrypted_notes.did.js";

export type BackendActor = ActorSubclass<_SERVICE>;

export function createActor(options?: {
  agentOptions?: HttpAgentOptions;
  actorOptions?: ActorConfig;
}): BackendActor {
  const hostOptions = {
    host:
      process.env.DFX_NETWORK === "ic"
        ? `https://${process.env.CANISTER_ID_ENCRYPTED_NOTES}.ic0.app`
        : "http://localhost:8000",
  };
  if (!options) {
    options = {
      agentOptions: hostOptions,
    };
  } else if (!options.agentOptions) {
    options.agentOptions = hostOptions;
  } else {
    options.agentOptions.host = hostOptions.host;
  }

  const agent = new HttpAgent({ ...options.agentOptions });
  // Fetch root key for certificate validation during development
  if (process.env.NODE_ENV !== "production") {
    console.log(`Dev environment - fetching root key...`);

    agent.fetchRootKey().catch((err) => {
      console.warn(
        "Unable to fetch root key. Check to ensure that your local replica is running"
      );
      console.error(err);
    });
  }

  // Creates an actor with using the candid interface and the HttpAgent
  return Actor.createActor(idlFactory, {
    agent,
    canisterId: process.env.CANISTER_ID_ENCRYPTED_NOTES,
    ...options?.actorOptions,
  });
}
