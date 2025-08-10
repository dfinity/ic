# Certificate Orchestrator

This directory contains the orchestration canister, which is used to coordinate
the work among the `certificate_issuer` services running on the boundary nodes
and to act as certificate and key store.

The canister:
* provides identity-based access to all its methods;
* maintains all registration requests and their current status;
* expires stale registration requests;
* automatically retries registration requests if it was not properly processed;
* schedules certificate renewals;
* stores all registered domains, alongside their certificate and private key.

## Settings

The canister relies on different constants that can be configured at build time:
* `REGISTRATION_EXPIRATION_TTL`: Time until a registration request that did not successfully complete is expired. Default value: 1h;
* `IN_PROGRESS_TTL`: Time until a task is retried if the assigned worker does not process the task (e.g., in case of worker failure). Default value: 10min;
* `REGISTRATION_RATE_LIMIT_RATE`: Number of permitted registration requests per time (see next constant). Default value: 5;
* `REGISTRATION_RATE_LIMIT_PERIOD`: Time period to which the rate-limit appliess. Default value: 1h;

## Deployment

To deploy the canister, you need to have `dfx` installed with an identity and a wallet.
You can find instructions in the [developer docs](https://internetcomputer.org/docs/current/developer-docs/quickstart/network-quickstart) on how to get started with `dfx`.

Then, you can deploy the canister on the IC with the following two commands:
```
export PRINCIPAL=$(dfx identity get-principal)
export ID_SEED=$(od -N 16 -t uL -An /dev/urandom | tr -d " ")
dfx deploy \
    --network "ic" \
    --argument "(
        record {
            rootPrincipals = vec {
                principal \"${PRINCIPAL}\";
            };
            idSeed = \"${ID_SEED}\";
        }
    )"
```

_Important:_ Make sure to use a random value of sufficient length for the ID seed.
The ID seed is a 128bit unsigned integer.
