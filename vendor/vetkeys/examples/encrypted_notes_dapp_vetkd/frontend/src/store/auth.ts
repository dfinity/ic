import { get, writable } from "svelte/store";
import { BackendActor, createActor } from "../lib/actor";
import { AuthClient } from "@dfinity/auth-client";
import { CryptoService } from "../lib/crypto";
import { addNotification, showError } from "./notifications";
import { sleep } from "../lib/sleep";
import type { JsonnableDelegationChain } from "@dfinity/identity/lib/cjs/identity/delegation";
import { navigateTo } from "svelte-router-spa";

export type AuthState =
  | {
      state: "initializing-auth";
    }
  | {
      state: "anonymous";
      actor: BackendActor;
      client: AuthClient;
    }
  | {
      state: "initializing-crypto";
      actor: BackendActor;
      client: AuthClient;
    }
  | {
      state: "synchronizing";
      actor: BackendActor;
      client: AuthClient;
    }
  | {
      state: "initialized";
      actor: BackendActor;
      client: AuthClient;
      crypto: CryptoService;
    }
  | {
      state: "error";
      error: string;
    };

export const auth = writable<AuthState>({
  state: "initializing-auth",
});

async function initAuth() {
  const client = await AuthClient.create();
  if (await client.isAuthenticated()) {
    authenticate(client);
  } else {
    auth.update(() => ({
      state: "anonymous",
      actor: createActor(),
      client,
    }));
  }
}

initAuth();

export function login() {
  const currentAuth = get(auth);

  if (currentAuth.state === "anonymous") {
    currentAuth.client.login({
      maxTimeToLive: BigInt(1800) * BigInt(1_000_000_000),
      identityProvider:
        process.env.DFX_NETWORK === "ic"
          ? "https://identity.ic0.app/#authorize"
          : `http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:8000/#authorize`,
      onSuccess: () => authenticate(currentAuth.client),
    });
  }
}

export async function logout() {
  const currentAuth = get(auth);

  if (currentAuth.state === "initialized") {
    await currentAuth.client.logout();
    auth.update(() => ({
      state: "anonymous",
      actor: createActor(),
      client: currentAuth.client,
    }));
    navigateTo("/");
  }
}

export async function authenticate(client: AuthClient) {
  handleSessionTimeout();

  try {
    const actor = createActor({
      agentOptions: {
        identity: client.getIdentity(),
      },
    });

    auth.update(() => ({
      state: "initializing-crypto",
      actor,
      client,
    }));

    const cryptoService = new CryptoService(actor);

    auth.update(() => ({
      state: "initialized",
      actor,
      client,
      crypto: cryptoService,
    }));
  } catch (e) {
    auth.update(() => ({
      state: "error",
      error: e.message || "An error occurred",
    }));
  }
}

// set a timer when the II session will expire and log the user out
function handleSessionTimeout() {
  // upon login the localstorage items may not be set, wait for next tick
  setTimeout(() => {
    try {
      const delegation = JSON.parse(
        window.localStorage.getItem("ic-delegation")
      ) as JsonnableDelegationChain;

      const expirationTimeMs =
        Number.parseInt(delegation.delegations[0].delegation.expiration, 16) /
        1000000;

      setTimeout(() => {
        logout();
      }, expirationTimeMs - Date.now());
    } catch {
      console.error("Could not handle delegation expiry.");
    }
  });
}
