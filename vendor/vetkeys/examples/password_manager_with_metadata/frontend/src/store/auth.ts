import "../lib/init.ts";
import { get, writable } from "svelte/store";
import { AuthClient } from "@dfinity/auth-client";
import type { JsonnableDelegationChain } from "@dfinity/identity/lib/cjs/identity/delegation";
import { replace } from "svelte-spa-router";
import {
    PasswordManager,
    createPasswordManager,
} from "../lib/password_manager.js";

export type AuthState =
    | {
          state: "initializing-auth";
      }
    | {
          state: "anonymous";
          client: AuthClient;
      }
    | {
          state: "initialized";
          passwordManager: PasswordManager;
          client: AuthClient;
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
        await authenticate(client);
    } else {
        auth.update(() => ({
            state: "anonymous",
            client,
        }));
    }
}

void initAuth();

export async function login() {
    const currentAuth = get(auth);

    if (currentAuth.state === "anonymous") {
        await currentAuth.client.login({
            maxTimeToLive: BigInt(1800) * BigInt(1_000_000_000),
            identityProvider:
                process.env.DFX_NETWORK === "ic"
                    ? "https://identity.ic0.app/#authorize"
                    : `http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:8000/#authorize`,
            onSuccess: async () => {
                await authenticate(currentAuth.client);
            },
            onError: (e) =>
                console.error(
                    "Failed to authenticate with internet identity: " + e,
                ),
        });
    }
}

export async function logout() {
    const currentAuth = get(auth);

    if (currentAuth.state === "initialized") {
        await currentAuth.client.logout();
        auth.update(() => ({
            state: "anonymous",
            client: currentAuth.client,
        }));
        await replace("/");
    }
}

export async function authenticate(client: AuthClient) {
    handleSessionTimeout();

    try {
        const passwordManager = await createPasswordManager({
            identity: client.getIdentity(),
        });

        auth.update(() => ({
            state: "initialized",
            passwordManager,
            client,
        }));
    } catch (e) {
        auth.update(() => ({
            state: "error",
            error: (e as Error).message || "An error occurred",
        }));
    }
}

// set a timer when the II session will expire and log the user out
function handleSessionTimeout() {
    // upon login the localstorage items may not be set, wait for next tick
    setTimeout(() => {
        try {
            const rawDelegation = window.localStorage.getItem("ic-delegation");
            if (!rawDelegation) {
                throw new Error("No delegation found");
            }
            const delegation = JSON.parse(
                rawDelegation,
            ) as JsonnableDelegationChain;

            const expirationTimeMs =
                Number.parseInt(
                    delegation.delegations[0].delegation.expiration,
                    16,
                ) / 1000000;

            setTimeout(() => {
                void logout();
            }, expirationTimeMs - Date.now());
        } catch (e) {
            console.error(
                "Could not handle delegation expiry: " + (e as Error).message,
            );
        }
    });
}
